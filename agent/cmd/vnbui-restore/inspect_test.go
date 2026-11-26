package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"vnbui/agent/internal/storagerestore"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectDefinitionUsesPrivateNewFile(t *testing.T) {
	chain, objects, _ := offlineFixture(t)
	var bundle struct {
		Schema  string                  `json:"schema"`
		Members []storagerestore.Member `json:"members"`
	}
	if err := readJSONFile(chain, &bundle, 32<<20, false); err != nil {
		t.Fatal(err)
	}
	last := &bundle.Members[len(bundle.Members)-1]
	source := last.Request.Plan.Source
	definition := map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"name": last.Request.Plan.VMName, "namespace": source.Namespace, "uid": source.VMUID, "resourceVersion": "10"}, "spec": map[string]interface{}{"template": map[string]interface{}{"spec": map[string]interface{}{"cloudInitUserData": "private-user-data"}}}}
	definitionBody, _ := json.Marshal(definition)
	for i, object := range last.Receipt.Objects {
		if object.Role == "volume_manifest" {
			path := filepath.Join(objects, last.Request.Plan.Target.Bucket, object.Key)
			var manifest map[string]interface{}
			if err := readJSONFile(path, &manifest, 16<<20, false); err != nil {
				t.Fatal(err)
			}
			manifest["vm_definition"] = base64.StdEncoding.EncodeToString(definitionBody)
			body, _ := json.Marshal(manifest)
			writeFile(t, path, body)
			last.Receipt.Objects[i].PlaintextBytes = int64(len(body))
			last.Receipt.Objects[i].CiphertextBytes = int64(len(body))
			last.Receipt.Objects[i].PlaintextSHA256 = checksum(body)
			last.Receipt.Objects[i].CiphertextSHA256 = checksum(body)
		}
	}
	writeJSON(t, chain, bundle)
	output := filepath.Join(t.TempDir(), "captured-vm.json")
	var stdout, stderr bytes.Buffer
	args := []string{"-chain", chain, "-objects-dir", objects, "-inspect-definition", output}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil || !bytes.Contains(body, []byte("private-user-data")) {
		t.Fatal(string(body), err)
	}
	if bytes.Contains(stdout.Bytes(), []byte("private-user-data")) {
		t.Fatal("VM secret leaked to stdout")
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if err := run(context.Background(), args, &stdout, &stderr); err == nil {
		t.Fatal("existing definition overwritten")
	}
}
