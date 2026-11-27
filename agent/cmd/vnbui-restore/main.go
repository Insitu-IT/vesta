// vesta-restore recovers file archives and accepted provider-specific VM chains.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/storagerestore"
)

var version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "vesta-restore:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 {
		switch args[0] {
		case "-version", "--version":
			_, err := fmt.Fprintln(stdout, "vesta-restore", version)
			return err
		case "-file-archive-format", "--file-archive-format":
			_, err := fmt.Fprintln(stdout, filearchive.Format)
			return err
		}
	}
	if len(args) != 0 && args[0] == "files" {
		return runFiles(ctx, args[1:], stdout, stderr)
	}
	if len(args) != 0 && args[0] == "s3" {
		return runS3(ctx, args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("vesta-restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	chainPath := flags.String("chain", "", "restore-bundle JSON exported by the backend")
	outputDir := flags.String("output", "", "new directory for verified raw disks; must not exist")
	definitionPath := flags.String("inspect-definition", "", "write selected receipt-bound VM definition to a NEW private file instead of reconstructing disks")
	verifyOnly := flags.Bool("verify-only", false, "stream-verify every admitted chain artifact without writing disks or creating a VM")
	objectsDir := flags.String("objects-dir", "", "offline object snapshot root, with files at <bucket>/<object-key>")
	s3Config := flags.String("s3-config", "", "private JSON file containing trusted S3 target and read credentials")
	keysDir := flags.String("keys-dir", "", "directory containing private <backup-id>.key files (base64 DEKs)")
	deadline := flags.String("deadline", "", "original absolute worker deadline; never renewed by pod scheduling")
	timeout := flags.Duration("timeout", 2*time.Hour, "maximum restore duration")
	workerPath := flags.String("worker", "", "controller-managed private worker input; writes only its fresh PVC mounts")
	workerCA := flags.String("worker-ca", "", "controller-projected S3 trust bundle for worker mode")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: vesta-restore -chain chain.json (-output NEW-DIRECTORY | -inspect-definition NEW-FILE | -verify-only) (-objects-dir ROOT | -s3-config FILE) [-keys-dir DIRECTORY]")
		filesUsage(stderr)
		s3Usage(stderr)
		fmt.Fprintln(stderr, "       vesta-restore --version | --file-archive-format")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *workerPath != "" {
		if flags.NArg() != 0 || *chainPath != "" || *outputDir != "" || *definitionPath != "" || *verifyOnly || *objectsDir != "" || *s3Config != "" || *keysDir != "" || *timeout <= 0 {
			return errors.New("worker input cannot be mixed with standalone restore flags")
		}
		if *deadline != "" {
			end, err := time.Parse(time.RFC3339Nano, *deadline)
			if err != nil || !time.Now().Before(end) {
				return errors.New("restore operation budget exhausted or invalid")
			}
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, end)
			defer cancel()
		}
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		return runWorker(ctx, *workerPath, *workerCA, stdout)
	}
	modes := 0
	for _, selected := range []bool{*outputDir != "", *definitionPath != "", *verifyOnly} {
		if selected {
			modes++
		}
	}
	if flags.NArg() != 0 || *chainPath == "" || modes != 1 || (*objectsDir == "") == (*s3Config == "") || *timeout <= 0 || *workerCA != "" || *deadline != "" {
		return errors.New("supply -chain, exactly one of -output/-inspect-definition/-verify-only, exactly one of -objects-dir/-s3-config, and a positive -timeout")
	}
	var raw json.RawMessage
	if err := readJSONFile(*chainPath, &raw, 32<<20, false); err != nil {
		return fmt.Errorf("read chain: %w", err)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return errors.New("invalid restore bundle")
	}
	var bundle struct {
		Schema  string                  `json:"schema"`
		Members []storagerestore.Member `json:"members"`
	}
	if header.Schema != nativerestore.BundleSchema {
		if err := readJSONFile(*chainPath, &bundle, 32<<20, false); err != nil {
			return fmt.Errorf("read chain: %w", err)
		}
	}
	if header.Schema != nativerestore.BundleSchema && (bundle.Schema != "vnbui-kubevirt-restore/1" || len(bundle.Members) == 0) {
		return errors.New("expected vnbui-kubevirt-restore/1 bundle with a full backup and any following incremental members")
	}

	var open storagerestore.ObjectOpener
	var closeSource func()
	var err error
	if *objectsDir != "" {
		open, closeSource, err = localSource(*objectsDir)
	} else {
		open, closeSource, err = s3Source(*s3Config)
	}
	if err != nil {
		return err
	}
	defer closeSource()
	keys, closeKeys, err := fileKeys(*keysDir)
	if err != nil {
		return err
	}
	defer closeKeys()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *verifyOnly {
		var result *storagerestore.VerificationResult
		if header.Schema == nativerestore.BundleSchema {
			var native nativerestore.Bundle
			native, err = nativerestore.DecodeBundle(raw)
			if err == nil {
				resolve := func(ctx context.Context, m nativerestore.Member) ([]byte, error) {
					return keys(ctx, storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: m.Request.BackupID}})
				}
				result, err = nativerestore.Verify(ctx, native, open, resolve)
			}
		} else {
			result, err = storagerestore.Verify(ctx, bundle.Members, open, keys)
		}
		if err != nil {
			return fmt.Errorf("verify chain: %w", err)
		}
		return json.NewEncoder(stdout).Encode(result)
	}
	if header.Schema == nativerestore.BundleSchema {
		return runNativeBundle(ctx, raw, *outputDir, *definitionPath, open, keys, stdout)
	}
	if *definitionPath != "" {
		definition, err := storagerestore.ReadVMDefinition(ctx, bundle.Members, open, keys)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(*definitionPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(definition)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			_ = os.Remove(*definitionPath)
			return errors.Join(err, closeErr)
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"definition_path": *definitionPath})
	}
	disks, err := storagerestore.Assemble(ctx, bundle.Members, *outputDir, open, keys)
	if err != nil {
		return fmt.Errorf("assemble chain: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Disks []storagerestore.Disk `json:"disks"`
	}{Disks: disks})
}

func readJSONFile(path string, dst any, limit int64, private bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("expected a regular file within the size limit")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return errors.New("credentials file must not be readable or writable by group/other (use mode 0600)")
	}
	decoder := json.NewDecoder(io.LimitReader(f, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
