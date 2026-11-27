package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/restoreinput"
	"vnbui/agent/internal/s3recovery"
	"vnbui/agent/internal/storagerestore"
)

func s3Usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: vesta-restore s3 list --s3-config FILE [--trust FILE | --kek-export FILE | --allow-unsigned-legacy | --file-prefix PREFIX]")
	fmt.Fprintln(w, "       vesta-restore s3 restore --s3-config FILE --backup UUID --output NEW-DIRECTORY [options]")
}

func runS3(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		s3Usage(stderr)
		return nil
	}
	restore := args[0] == "restore"
	if !restore && args[0] != "list" {
		return errors.New("expected s3 list or s3 restore")
	}
	flags := flag.NewFlagSet("vesta-restore s3 "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		s3Usage(stderr)
		flags.PrintDefaults()
	}
	config := flags.String("s3-config", "", "private S3 read credential and HTTPS target configuration")
	trustPath := flags.String("trust", "", "independently saved trust document for signed VM recovery points")
	keyExportPath := flags.String("kek-export", "", "private Vesta local key export (version 1); may include trusted recovery key")
	passphrasePath := flags.String("passphrase-file", "", "private passphrase file; otherwise prompt on the controlling terminal")
	legacy := flags.Bool("allow-unsigned-legacy", false, "acknowledge unsigned historical metadata for recovery to a new isolated local directory")
	files := flags.String("file-prefix", "", "locally approved host prefix containing managed-files archives")
	set := flags.String("set", "", "managed file set name for discovery or exact selection")
	org := flags.String("org-id", "", "organization UUID limiting the unsigned legacy search")
	installation := flags.String("installation-id", "", "independently known source installation UUID for unsigned legacy recovery; requires --org-id")
	generationKey := flags.String("generation-key", "", "exact unsigned legacy generation object key")
	var selected selections
	var backupID, output, versionID, identityPath, digest string
	flags.StringVar(&versionID, "version-id", "", "exact metadata or archive version (required for managed file restore)")
	pageOptions := s3recovery.PageOptions{Limit: 100}
	if !restore {
		flags.IntVar(&pageOptions.Limit, "limit", 100, "maximum S3 version entries per page, including hidden historical versions")
		flags.StringVar(&pageOptions.Cursor, "cursor", "", "continue a listing using the previous page's next_cursor")
	}
	defaultTimeout := 10 * time.Minute
	if restore {
		defaultTimeout = 2 * time.Hour
		flags.StringVar(&backupID, "backup", "", "backup UUID shown by s3 list")
		flags.StringVar(&output, "output", "", "new destination directory")
		flags.StringVar(&identityPath, "identity", "", "private age identity file (managed files)")
		flags.StringVar(&digest, "sha256", "", "optional trusted ciphertext digest for a managed file archive")
		flags.Var(&selected, "select", "archive-relative file or directory (repeatable; managed files)")
	}
	timeout := flags.Duration("timeout", defaultTimeout, "maximum S3 discovery or restore duration")
	if err := flags.Parse(args[1:]); err != nil {
		return fileFlagError(err)
	}
	fileMode := *files != ""
	if flags.NArg() != 0 || *config == "" || *timeout <= 0 || pageOptions.Limit < 1 || pageOptions.Limit > 1000 ||
		(restore && (!s3recovery.ValidID(backupID) || output == "")) ||
		(versionID != "" && (!restoreinput.ValidVersion(versionID) || (!restore && !*legacy) ||
			(*legacy && *generationKey == ""))) ||
		(*passphrasePath != "" && *keyExportPath == "") ||
		(*org != "" && (!*legacy || !s3recovery.ValidID(*org))) ||
		(*installation != "" && (!*legacy || *org == "" || !s3recovery.ValidID(*installation))) ||
		(*generationKey != "" && !*legacy) {
		return errors.New("supply private --s3-config and compatible discovery options; restore also requires --backup UUID and --output NEW-DIRECTORY")
	}
	if fileMode {
		if *legacy || *trustPath != "" || *keyExportPath != "" || (restore && (identityPath == "" || versionID == "")) {
			return errors.New("managed file restore requires --identity and --version-id; VM trust and key options are separate")
		}
	} else if *set != "" || identityPath != "" || digest != "" || len(selected) != 0 {
		return errors.New("file set, age identity, digest and archive selection require --file-prefix")
	}

	var export *s3recovery.KeyExport
	if *keyExportPath != "" {
		var err error
		export, err = s3recovery.OpenKeyExport(*keyExportPath, *passphrasePath, stderr)
		if err != nil {
			return err
		}
		defer export.Close()
	}
	var trust s3recovery.Trust
	if export != nil && export.Trust != nil {
		trust = *export.Trust
	}
	if *trustPath != "" {
		raw, err := s3recovery.ReadFile(*trustPath, 64<<10, false)
		if err != nil {
			return err
		}
		local, err := s3recovery.DecodeTrust(raw)
		if err != nil {
			return err
		}
		if trust.InstallationID != "" && trust != local {
			return errors.New("independent trust and KEK export refer to different recovery scopes")
		}
		trust = local
	}
	if !fileMode && !*legacy && trust.InstallationID == "" {
		return errors.New("signed VM recovery requires independent --trust or a trusted recovery key inside --kek-export")
	}
	var legacyScope *s3recovery.LegacyScope
	if *legacy {
		if trust.InstallationID != "" {
			if (*installation != "" && *installation != trust.InstallationID) || (*org != "" && *org != trust.OrgID) {
				return errors.New("explicit source installation or organization differs from independent recovery trust")
			}
			*installation, *org = trust.InstallationID, trust.OrgID
		}
		if *installation != "" {
			legacyScope = &s3recovery.LegacyScope{InstallationID: *installation, OrgID: *org}
		}
	}
	bucket, closeBucket, err := restoreinput.OpenBucket(*config, fileMode)
	if err != nil {
		return err
	}
	defer closeBucket()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	query := s3recovery.Query{BackupID: backupID, GenerationKey: *generationKey, VersionID: versionID, OrgID: *org, LegacyScope: legacyScope}
	if !restore {
		var items s3recovery.CatalogPage
		switch {
		case fileMode:
			items, err = s3recovery.ListFiles(ctx, bucket, *files, *set, pageOptions)
		case *legacy:
			items, err = s3recovery.ListLegacy(ctx, bucket, query, pageOptions)
		default:
			items, err = s3recovery.ListSigned(ctx, bucket, trust, pageOptions)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(items)
	}
	if fileMode {
		identity, err := filearchive.LoadIdentity(identityPath)
		if err != nil {
			return err
		}
		item, pin, err := s3recovery.FindFile(ctx, bucket, *files, *set, query)
		if err != nil {
			return err
		}
		body, err := bucket.Get(ctx, pin)
		if err != nil {
			return err
		}
		defer body.Close()
		summary, err := filearchive.Extract(ctx, body, filearchive.ReadOptions{Identity: identity, ExpectedSHA256: digest}, output, selected)
		if err != nil {
			return err
		}
		item.Status = "archive-verified"
		return json.NewEncoder(stdout).Encode(struct {
			Backup  s3recovery.Item     `json:"backup"`
			Format  string              `json:"format"`
			Summary filearchive.Summary `json:"summary"`
			Output  string              `json:"output"`
		}{item, filearchive.Format, summary, output})
	}
	var item s3recovery.Item
	var plan s3recovery.Plan
	if *legacy {
		_, _ = fmt.Fprintln(stderr, "Unsigned historical metadata is untrusted. Recovery writes verified disk output to a new local directory.")
		item, plan, err = s3recovery.FindLegacy(ctx, bucket, query)
	} else {
		item, plan, err = s3recovery.FindSigned(ctx, bucket, trust, query)
	}
	if err != nil {
		return err
	}
	return recoverBucketDisks(ctx, bucket, plan, item, export, output, legacyScope, stdout)
}

func recoverBucketDisks(ctx context.Context, bucket *restoreinput.Bucket, plan s3recovery.Plan, item s3recovery.Item, keys *s3recovery.KeyExport, output string, scope *s3recovery.LegacyScope, stdout io.Writer) error {
	if err := plan.CheckKeys(keys); err != nil {
		return err
	}
	final, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("restore output must be a new directory")
	}
	if item.Trust == "unsigned-legacy" {
		if err := checkLegacySpace(filepath.Dir(final), plan); err != nil {
			return err
		}
	}
	folder, err := os.MkdirTemp(filepath.Dir(final), ".vesta-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(folder)
	stage := filepath.Join(folder, "verified")
	resolve := plan.Keys(keys)
	var disks any
	if len(plan.Native.Members) != 0 {
		native, err := restoreNativeDisks(ctx, plan.Native, stage, bucket.Open, resolve, true)
		if err != nil {
			return err
		}
		for i := range native {
			native[i].Path, err = publishedPath(stage, final, native[i].Path)
			if err != nil {
				return err
			}
		}
		disks = native
	} else {
		vm, err := storagerestore.Assemble(ctx, plan.VM, stage, bucket.Open, resolve)
		if err != nil {
			return err
		}
		for i := range vm {
			vm[i].Path, err = publishedPath(stage, final, vm[i].Path)
			if err != nil {
				return err
			}
		}
		disks = vm
	}
	if item.Trust == "unsigned-legacy" {
		if err := s3recovery.ConfirmUnsigned(ctx, bucket, item.BackupID, scope); err != nil {
			return err
		}
	}
	if err := publishVerifiedDisks(ctx, stage, final, (*os.File).Sync); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		Backup s3recovery.Item `json:"backup"`
		Disks  any             `json:"disks"`
	}{item, disks})
}

func publishedPath(stage, final, name string) (string, error) {
	rel, err := filepath.Rel(stage, name)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return "", errors.New("provider produced a disk path outside the isolated restore directory")
	}
	return filepath.Join(final, rel), nil
}

func checkLegacySpace(parent string, plan s3recovery.Plan) error {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(parent, &filesystem); err != nil {
		return err
	}
	if filesystem.Bsize <= 0 {
		return errors.New("cannot determine restore filesystem block size")
	}
	blockSize := uint64(filesystem.Bsize)
	available := uint64(math.MaxInt64)
	if uint64(filesystem.Bavail) <= available/blockSize {
		available = uint64(filesystem.Bavail) * blockSize
	}
	fits := func(size int64) bool {
		if size < 0 || uint64(size) > available {
			return false
		}
		available -= uint64(size)
		return true
	}
	spaceError := errors.New("isolated recovery destination has insufficient available space for the declared disks and scratch")
	if len(plan.Native.Members) != 0 {
		for _, member := range plan.Native.Members {
			for _, object := range member.Receipt.Objects {
				if !fits(object.PlaintextBytes) {
					return spaceError
				}
			}
			for _, disk := range member.PushResult.Manifest.Disks {
				if !fits(disk.SizeBytes) {
					return spaceError
				}
			}
		}
		last := plan.Native.Members[len(plan.Native.Members)-1]
		for _, disk := range last.PushResult.Manifest.Disks {
			if !fits(disk.VirtualSize) {
				return spaceError
			}
		}
	} else {
		for _, disk := range plan.VM[0].Request.Plan.Source.Volumes {
			if !fits(disk.CapacityBytes) {
				return spaceError
			}
		}
	}
	return nil
}
