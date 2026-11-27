package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/restoreinput"
)

type selections []string

func (s *selections) String() string { return strings.Join(*s, ", ") }
func (s *selections) Set(name string) error {
	*s = append(*s, name)
	return nil
}

func filesUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: vesta-restore files keygen|recipient --identity FILE")
	fmt.Fprintln(w, "       vesta-restore files verify|list|extract --archive PATH-OR-S3-URI --identity FILE [options]")
}

func runFiles(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		filesUsage(stderr)
		return nil
	}
	command := args[0]
	flags := flag.NewFlagSet("vesta-restore files "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		filesUsage(stderr)
		flags.PrintDefaults()
	}
	identityPath := flags.String("identity", "", "private native age identity file (keygen requires a new file)")
	switch command {
	case "keygen", "recipient":
		if err := flags.Parse(args[1:]); err != nil {
			return fileFlagError(err)
		}
		if flags.NArg() != 0 || *identityPath == "" {
			return errors.New("supply --identity FILE")
		}
		var recipient string
		if command == "keygen" {
			generated, err := filearchive.CreateIdentity(*identityPath)
			if err != nil {
				return err
			}
			recipient = generated
		} else {
			identity, err := filearchive.LoadIdentity(*identityPath)
			if err != nil {
				return err
			}
			recipient = identity.Recipient()
		}
		_, err := fmt.Fprintln(stdout, recipient)
		return err
	case "verify", "list", "extract":
	default:
		return errors.New("expected file archive command keygen, recipient, verify, list or extract")
	}
	archive := flags.String("archive", "", "local archive file or s3://bucket/object-key")
	s3Config := flags.String("s3-config", "", "private JSON file containing trusted S3 target and read credentials")
	s3Version := flags.String("s3-version-id", "", "exact S3 object version, when available")
	digest := flags.String("sha256", "", "expected SHA-256 of the encrypted object from a trusted backup receipt")
	timeout := flags.Duration("timeout", 2*time.Hour, "maximum verification or recovery duration")
	var output string
	var selected selections
	if command == "extract" {
		flags.StringVar(&output, "output", "", "new destination directory")
		flags.Var(&selected, "select", "archive-relative file or directory to restore (repeatable)")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return fileFlagError(err)
	}
	if flags.NArg() != 0 || *archive == "" || *identityPath == "" || *timeout <= 0 || (command == "extract" && output == "") {
		return errors.New("supply --archive, --identity, a positive timeout and, for extraction, --output")
	}
	identity, err := filearchive.LoadIdentity(*identityPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	input, closeSource, err := openFileArchive(ctx, *archive, *s3Config, *s3Version)
	if err != nil {
		return err
	}
	defer closeSource()
	defer input.Close()
	options := filearchive.ReadOptions{Identity: identity, ExpectedSHA256: *digest}
	var summary filearchive.Summary
	switch command {
	case "list":
		_, err := filearchive.List(ctx, input, options, stdout)
		return err
	case "verify":
		summary, err = filearchive.Verify(ctx, input, options)
	case "extract":
		summary, err = filearchive.Extract(ctx, input, options, output, selected)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		Format  string              `json:"format"`
		Summary filearchive.Summary `json:"summary"`
		Output  string              `json:"output,omitempty"`
	}{filearchive.Format, summary, output})
}

func fileFlagError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func openFileArchive(ctx context.Context, archive, config, version string) (io.ReadCloser, func(), error) {
	if strings.HasPrefix(archive, "s3://") {
		if config == "" {
			return nil, nil, errors.New("S3 file archives require --s3-config")
		}
		uri, err := url.Parse(archive)
		if err != nil || uri.Host == "" || uri.User != nil || uri.Port() != "" ||
			uri.RawQuery != "" || uri.ForceQuery || strings.Contains(archive, "#") || uri.Opaque != "" {
			return nil, nil, errors.New("expected a literal s3://bucket/object-key archive URI")
		}
		return restoreinput.OpenS3Archive(ctx, config, uri.Host, strings.TrimPrefix(uri.Path, "/"), version)
	}
	if config != "" || version != "" || strings.Contains(archive, "://") {
		return nil, nil, errors.New("supply a local file path, or use s3://bucket/object-key with --s3-config")
	}
	f, err := filearchive.OpenLocal(archive)
	if err != nil {
		return nil, nil, fmt.Errorf("open offline archive: %w", err)
	}
	return f, func() {}, nil
}
