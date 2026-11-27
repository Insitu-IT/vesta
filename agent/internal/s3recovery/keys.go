package s3recovery

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fernet/fernet-go"
	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

const maxExport = 4 << 20
const maxPassphrase = 4096

type keyEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Material  string `json:"key_material"`
	KeyHash   string `json:"key_hash"`
	CreatedAt string `json:"created_at"`
}

type KeyExport struct {
	Trust *Trust
	keys  map[string][]byte
}

func (k *KeyExport) Close() {
	for _, key := range k.keys {
		clear(key)
	}
	clear(k.keys)
}

// ReadFile opens an ordinary operator file without following a final symlink
// or blocking on a named pipe. Secret inputs must be owner-only.
func ReadFile(name string, max int, private bool) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open recovery input file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(max) ||
		(private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("expected a bounded regular recovery input file and mode 0600 for secrets")
	}
	body, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(body) > max {
		return nil, errors.New("cannot read bounded recovery input")
	}
	return body, nil
}

func OpenKeyExport(filename, passphraseFile string, stderr io.Writer) (*KeyExport, error) {
	raw, err := ReadFile(filename, maxExport, true)
	if err != nil {
		return nil, err
	}
	var pass []byte
	if passphraseFile != "" {
		pass, err = ReadFile(passphraseFile, maxPassphrase, true)
	} else {
		tty, openErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if openErr != nil {
			return nil, errors.New("a private --passphrase-file is required without a controlling terminal")
		}
		defer tty.Close()
		_, _ = fmt.Fprint(stderr, "Recovery key export passphrase: ")
		pass, err = term.ReadPassword(int(tty.Fd()))
		_, _ = fmt.Fprintln(stderr)
	}
	defer clear(pass)
	if err != nil || len(pass) == 0 || len(pass) > maxPassphrase {
		return nil, errors.New("cannot read recovery key export passphrase")
	}
	export, err := unlockKeyExport(raw, pass)
	if passphraseFile != "" && errors.Is(err, errKeyAuthentication) && bytes.HasSuffix(pass, []byte("\n")) {
		// A passphrase file can contain a conventional line ending. Exact
		// bytes take precedence, including genuine trailing whitespace.
		line := bytes.TrimSuffix(bytes.TrimSuffix(pass, []byte("\n")), []byte("\r"))
		if len(line) != 0 {
			return unlockKeyExport(raw, line)
		}
	}
	return export, err
}

var errKeyAuthentication = errors.New("recovery key export authentication failed; check the passphrase and file")

func unlockKeyExport(raw, pass []byte) (*KeyExport, error) {
	if len(raw) <= 16 || len(raw) > maxExport {
		return nil, errors.New("invalid recovery key export")
	}
	// A Fernet token must include a version, timestamp, IV, at least one
	// ciphertext block and HMAC before it can be passed to the library.
	const overhead = 1 + 8 + aes.BlockSize + sha256.Size
	token, err := decode64(base64.URLEncoding, string(raw[16:]))
	if err != nil || len(token) < overhead+aes.BlockSize || (len(token)-overhead)%aes.BlockSize != 0 {
		return nil, errors.New("invalid recovery key export token")
	}
	derived, err := pbkdf2.Key(sha256.New, string(pass), raw[:16], 600000, 32)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	var fernetKey fernet.Key
	copy(fernetKey[:], derived)
	defer clear(fernetKey[:])
	// A KEK export is intended for long-term offline recovery.
	plain := fernet.VerifyAndDecrypt(raw[16:], 0, []*fernet.Key{&fernetKey})
	if plain == nil {
		return nil, errKeyAuthentication
	}
	defer clear(plain)
	var payload struct {
		Version    int             `json:"version"`
		Format     string          `json:"format"`
		ExportedAt string          `json:"exported_at"`
		Keys       []keyEntry      `json:"keys"`
		Trust      json.RawMessage `json:"recovery_trust"`
	}
	wire, err := models.DecodeStorageControlJSONBounded(plain, maxExport)
	if err != nil || !fields(wire, "version format exported_at keys", "recovery_trust") ||
		json.Unmarshal(plain, &payload) != nil || payload.Version != 1 || payload.Format != "vnbui-key-export" ||
		payload.Keys == nil || len(payload.Keys) > 4096 || payload.ExportedAt == "" {
		return nil, errors.New("unsupported recovery key export")
	}
	result := &KeyExport{keys: make(map[string][]byte)}
	valid := false
	defer func() {
		if !valid {
			result.Close()
		}
	}()
	rawEntries := wire["keys"].([]any)
	for i, entry := range payload.Keys {
		obj, ok := rawEntries[i].(map[string]any)
		if !ok || !fields(obj, "id name algorithm key_material key_hash created_at", "") ||
			!ValidID(entry.ID) || entry.Algorithm != "aes-256-gcm" {
			return nil, errors.New("invalid recovery KEK export entry")
		}
		key, err := decode64(base64.StdEncoding, entry.Material)
		if err != nil || len(key) != 32 || (len(entry.KeyHash) != 16 && len(entry.KeyHash) != 64) || entry.KeyHash != hash(key)[:len(entry.KeyHash)] {
			clear(key)
			return nil, errors.New("recovery KEK fingerprint check failed")
		}
		ref := "kek:" + entry.ID + ":" + entry.KeyHash
		if result.keys[ref] != nil {
			clear(key)
			return nil, errors.New("duplicate recovery KEK identity")
		}
		result.keys[ref] = key
	}
	if len(payload.Trust) != 0 && !bytes.Equal(payload.Trust, []byte("null")) {
		trust, err := DecodeTrust(payload.Trust)
		if err != nil {
			return nil, err
		}
		result.Trust = &trust
	}
	if len(result.keys) == 0 && result.Trust == nil {
		return nil, errors.New("empty recovery key export")
	}
	valid = true
	return result, nil
}

type wrappedKey struct {
	Schema        int    `json:"schema"`
	OrgID         string `json:"org_id"`
	BackupID      string `json:"backup_id"`
	ReservationID string `json:"reservation_id"`
	AttemptID     string `json:"attempt_id"`
	PlanSHA256    string `json:"plan_sha256"`
	KeyRef        string `json:"key_ref"`
	Format        string `json:"format"`
	Wrapping      string `json:"wrapping"`
	Ciphertext    string `json:"ciphertext"`
}

func decodeWrapped(raw json.RawMessage, expected wrappedKey) (wrappedKey, error) {
	var key wrappedKey
	if models.DecodeStorageValue(raw, &key, 4096) != nil {
		return key, errors.New("missing or malformed wrapped attempt key")
	}
	expected.Ciphertext = key.Ciphertext
	ciphertext, err := decode64(base64.StdEncoding, key.Ciphertext)
	if key != expected || err != nil || len(ciphertext) != 40 {
		return key, errors.New("wrapped attempt key does not match its accepted plan")
	}
	return key, nil
}

func (p Plan) CheckKeys(export *KeyExport) error {
	for backup, saved := range p.wrapped {
		if export == nil || export.keys[saved.KeyRef] == nil {
			return fmt.Errorf("encrypted backup %s requires its KEK in a private --kek-export", backup)
		}
	}
	return nil
}

func (p Plan) Keys(export *KeyExport) storagerestore.KeyResolver {
	return func(ctx context.Context, member storagerestore.Member) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		saved := p.wrapped[member.Request.BackupID]
		if export == nil || export.keys[saved.KeyRef] == nil {
			return nil, fmt.Errorf("encrypted backup %s requires its KEK in a private --kek-export", member.Request.BackupID)
		}
		block, err := aes.NewCipher(export.keys[saved.KeyRef])
		if err != nil {
			return nil, errors.New("invalid retained recovery KEK")
		}
		ciphertext, err := decode64(base64.StdEncoding, saved.Ciphertext)
		if err != nil {
			return nil, errors.New("invalid wrapped attempt key")
		}
		clearKey, err := josecipher.KeyUnwrap(block, ciphertext)
		if err != nil || len(clearKey) != 32 {
			clear(clearKey)
			return nil, errors.New("attempt key authentication failed")
		}
		return clearKey, nil
	}
}
