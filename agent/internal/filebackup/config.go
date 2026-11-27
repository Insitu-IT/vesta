package filebackup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/files3"
)

const maxConfigBytes = 64 << 10

var (
	setName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	prefix  = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$`)
)

type set struct {
	Name      string `json:"name"`
	Root      string `json:"root"`
	Recipient string `json:"recipient"`
}

type configuration struct {
	Sets     []set                  `json:"sets"`
	S3       map[string]interface{} `json:"s3"`
	MaxBytes int64                  `json:"max_archive_bytes"`
	S3CAFile string                 `json:"s3_ca_file"`
}

func loadConfig(path, stateDir string) (configuration, *backup.S3Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return configuration{}, nil, fmt.Errorf("open managed file backup configuration: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 ||
		info.Size() > maxConfigBytes {
		return configuration{}, nil, errors.New("managed file backup configuration must be a private regular file, at most 64 KiB")
	}

	var cfg configuration
	decoder := json.NewDecoder(io.LimitReader(f, maxConfigBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil || decoder.Decode(new(any)) != io.EOF {
		return configuration{}, nil, errors.New("invalid managed file backup configuration")
	}
	if len(cfg.Sets) == 0 || len(cfg.Sets) > 64 {
		return configuration{}, nil, errors.New("declare between 1 and 64 managed file sets")
	}
	seen := make(map[string]bool, len(cfg.Sets))
	for _, source := range cfg.Sets {
		if !ValidName(source.Name) || seen[source.Name] {
			return configuration{}, nil, fmt.Errorf("invalid or duplicate managed file set name %q", source.Name)
		}
		seen[source.Name] = true
		if !filepath.IsAbs(source.Root) || filepath.Clean(source.Root) != source.Root || overlaps(source.Root, stateDir) {
			return configuration{}, nil, fmt.Errorf("file set %q requires a clean absolute root separate from the job state directory", source.Name)
		}
		if err := filearchive.ValidateRecipient(source.Recipient); err != nil {
			return configuration{}, nil, fmt.Errorf("file set %q requires an age X25519 public recipient", source.Name)
		}
	}
	s3, err := parseFileStorage(cfg.S3)
	if err != nil || s3 == nil || s3.AccessKey == "" || s3.SecretKey == "" || !s3.UseSSL ||
		!prefix.MatchString(s3.Prefix) || len(s3.Prefix) > 512 {
		return configuration{}, nil, errors.New("managed file backups require HTTPS S3 with scoped credentials and a nonempty prefix")
	}
	for _, part := range strings.Split(s3.Prefix, "/") {
		if part == "." || part == ".." {
			return configuration{}, nil, errors.New("managed file backup S3 prefix contains a dot segment")
		}
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 32 << 30
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > 5<<40 {
		return configuration{}, nil, errors.New("managed file backup max_archive_bytes must be between 1 byte and 5 TiB")
	}
	return cfg, s3, nil
}

// parseFileStorage computes the exact storage origin used by the S3 client
// before advertising or admitting it. Explicitly empty endpoint selects AWS.
func parseFileStorage(raw map[string]interface{}) (*backup.S3Config, error) {
	value := make(map[string]interface{}, len(raw)+2)
	for key, entry := range raw {
		value[key] = entry
	}
	endpoint, ok := value["endpoint"].(string)
	if !ok && value["endpoint"] != nil {
		return nil, errors.New("file backup S3 endpoint must be an HTTPS origin")
	}
	region, ok := value["region"].(string)
	if !ok && value["region"] != nil {
		return nil, errors.New("file backup S3 region must be a string")
	}
	endpoint, region, err := files3.Normalize(endpoint, strings.TrimSpace(region))
	if err != nil {
		return nil, err
	}
	value["endpoint"], value["region"] = endpoint, region
	return backup.ParseS3Config(value)
}

func overlaps(a, b string) bool {
	below := func(root, child string) bool {
		rel, err := filepath.Rel(root, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return below(a, b) || below(b, a)
}

func ValidName(name string) bool {
	return setName.MatchString(name)
}
