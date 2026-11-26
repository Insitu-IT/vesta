package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

func verificationCLIFixture(t *testing.T) (chain, objects, payload string) {
	t.Helper()
	chain, objects, payload = offlineFixture(t)
	var bundle struct {
		Schema  string                  `json:"schema"`
		Members []storagerestore.Member `json:"members"`
	}
	if err := readJSONFile(chain, &bundle, 32<<20, false); err != nil {
		t.Fatal(err)
	}
	for i := range bundle.Members {
		m := &bundle.Members[i]
		if i > 0 {
			_, digest, err := models.CanonicalReceipt(&bundle.Members[i-1].Request, bundle.Members[i-1].Receipt)
			if err != nil {
				t.Fatal(err)
			}
			m.Request.Plan.Parent.ReceiptSHA256 = digest
			body, _ := models.StorageCanonical(m.Request.Plan)
			m.Request.PlanSHA256 = checksum(body)
		}
		s := m.Request.Plan.Source
		definition, _ := json.Marshal(map[string]any{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]any{"namespace": s.Namespace, "name": m.Request.Plan.VMName, "uid": s.VMUID, "resourceVersion": "10"}, "spec": map[string]any{"private-example": "must-not-appear-in-report"}})
		for j, o := range m.Receipt.Objects {
			if o.Role != "volume_manifest" {
				continue
			}
			path := filepath.Join(objects, m.Request.Plan.Target.Bucket, o.Key)
			var manifest map[string]any
			if err := readJSONFile(path, &manifest, 16<<20, false); err != nil {
				t.Fatal(err)
			}
			manifest["vm_definition"] = base64.StdEncoding.EncodeToString(definition)
			body, _ := json.Marshal(manifest)
			writeFile(t, path, body)
			m.Receipt.Objects[j].PlaintextBytes = int64(len(body))
			m.Receipt.Objects[j].CiphertextBytes = int64(len(body))
			m.Receipt.Objects[j].PlaintextSHA256 = checksum(body)
			m.Receipt.Objects[j].CiphertextSHA256 = checksum(body)
		}
	}
	writeJSON(t, chain, bundle)
	return
}

func TestVerifyOnlyCLIStreamsWithoutCreatingOutput(t *testing.T) {
	chain, objects, _ := verificationCLIFixture(t)
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-verify-only"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	var result storagerestore.VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Schema != storagerestore.VerificationSchema || result.Provider != "kubevirt" || len(result.Members) != 2 {
		t.Fatal(stdout.String(), err)
	}
	if bytes.Contains(stdout.Bytes(), []byte("must-not-appear-in-report")) {
		t.Fatal("captured private VM data leaked")
	}
	entries, err := os.ReadDir(filepath.Dir(chain))
	if err != nil || len(entries) != 2 {
		t.Fatal("verification created files", entries, err)
	}
	for _, member := range result.Members {
		if member.Objects != 2 || member.ReceiptSHA256 == "" {
			t.Fatal(member)
		}
	}
}

func TestVerifyOnlyCLIHasNoSuccessfulOutputOnCorruption(t *testing.T) {
	chain, objects, payload := verificationCLIFixture(t)
	writeFile(t, payload, []byte("zz"))
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-verify-only"}, &stdout, io.Discard); err == nil || stdout.Len() != 0 {
		t.Fatal("corruption returned success", stdout.String(), err)
	}
}

func TestVerifyOnlyCLIRejectsRestoreModesAndNativeInvalidBundle(t *testing.T) {
	chain, objects, _ := verificationCLIFixture(t)
	for _, extra := range [][]string{{"-output", filepath.Join(t.TempDir(), "must-not-exist")}, {"-inspect-definition", filepath.Join(t.TempDir(), "must-not-exist")}, {"-worker", "input.json"}} {
		args := append([]string{"-chain", chain, "-objects-dir", objects, "-verify-only"}, extra...)
		var stdout bytes.Buffer
		if err := run(context.Background(), args, &stdout, io.Discard); err == nil || stdout.Len() != 0 {
			t.Fatal("mixed worker/restore mode admitted")
		}
		if _, err := os.Stat(extra[1]); !os.IsNotExist(err) {
			t.Fatal("mixed mode created output", err)
		}
	}
	writeJSON(t, chain, map[string]any{"schema": "vnbui-native-restore/1", "members": []any{}})
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-verify-only"}, &stdout, io.Discard); err == nil || stdout.Len() != 0 {
		t.Fatal("invalid native chain returned proof")
	}
}
