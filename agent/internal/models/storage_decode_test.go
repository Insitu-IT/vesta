package models

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"vnbui/agent/internal/encryption"
)

func TestEncryptedPlanMatchesExistingProducer(t *testing.T) {
	baseline, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{1, 5242879, 5242880, 5242881, 10485760} {
		t.Run(strconv.FormatInt(size, 10), func(t *testing.T) {
			var r StorageTransactionRequest
			if err := json.Unmarshal(baseline, &r); err != nil {
				t.Fatal(err)
			}
			r.Plan.Source.Volumes[0].CapacityBytes = size
			ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
			r.Plan.Encryption.Format, r.Plan.Encryption.KeyRef = "vnbu1-aes256gcm-chunk5242880", &ref
			a := &r.Plan.Artifacts[1]
			a.PlaintextMax, a.CiphertextMin = size, 5
			a.CiphertextMax = 5 + size + 32*((size+5242880-1)/5242880)
			if _, err := DecodeStorageTransaction(hashedStorageBody(t, r)); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := encryption.EncryptStreamChunked(bytes.NewReader(make([]byte, int(size))), &output, make([]byte, 32), 5242880); err != nil {
				t.Fatal(err)
			}
			if int64(output.Len()) != a.CiphertextMax || string(output.Bytes()[:4]) != "VNBU" || output.Bytes()[4] != 1 {
				t.Fatal("producer framing drift")
			}
			a.CiphertextMax--
			if _, err := DecodeStorageTransaction(hashedStorageBody(t, r)); err == nil {
				t.Fatal("accepted incorrect encrypted bound")
			}
		})
	}
}

func hashedStorageBody(t *testing.T, request StorageTransactionRequest) []byte {
	t.Helper()
	body, err := json.Marshal(request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var plan any
	if err := decoder.Decode(&plan); err != nil {
		t.Fatal(err)
	}
	request.PlanSHA256, err = storagePlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStorageWireProfileAndVersionRefusal(t *testing.T) {
	baseline, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var request StorageTransactionRequest
	if err := json.Unmarshal(baseline, &request); err != nil {
		t.Fatal(err)
	}
	for _, profile := range StorageProfiles() {
		request.Plan.CapabilityProfile = profile
		body := hashedStorageBody(t, request)
		if _, err := DecodeStorageTransaction(body); err != nil {
			t.Fatal(err)
		}
		var changed map[string]any
		if err := json.Unmarshal(body, &changed); err != nil {
			t.Fatal(err)
		}
		for _, digest := range []string{"", "wrong", strings.Repeat("0", 64), strings.ToUpper(changed["plan_sha256"].(string))} {
			changed["plan_sha256"] = digest
			invalid, _ := json.Marshal(changed)
			if _, err := DecodeStorageTransaction(invalid); err == nil {
				t.Fatal("accepted invalid plan digest")
			}
		}
		// Changing a well-typed field must invalidate the original digest.
		changed = nil
		if err := json.Unmarshal(body, &changed); err != nil {
			t.Fatal(err)
		}
		changed["plan"].(map[string]any)["vm_name"] = "replacement"
		invalid, _ := json.Marshal(changed)
		if _, err := DecodeStorageTransaction(invalid); err == nil {
			t.Fatal("accepted plan mutation under original digest")
		}
	}
	for _, body := range [][]byte{
		[]byte(`{"protocol":"vnbui-storage-transaction/1","protocol":"other"}`),
		[]byte(`null`), []byte(`{}`),
	} {
		if _, err := DecodeStorageTransaction(body); err == nil {
			t.Fatal("accepted malformed envelope")
		}
	}
	request.Plan.CapabilityProfile = "unknown/1"
	body, _ := json.Marshal(request)
	if _, err := DecodeStorageTransaction(body); err == nil {
		t.Fatal("accepted unknown profile")
	}
	request.Plan.CapabilityProfile = StorageProfiles()[0]
	request.Protocol = "vnbui-storage-transaction/2"
	body, _ = json.Marshal(request)
	if _, err := DecodeStorageTransaction(body); err == nil {
		t.Fatal("accepted unknown protocol")
	}
}

func TestStorageSemanticCorpus(t *testing.T) {
	baseline, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStorageTransaction(baseline); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../contracts/storage_semantic_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string `json:"name"`
		Accepted bool   `json:"accepted"`
		Changes  []struct {
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"changes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 67 {
		t.Fatal("semantic corpus unexpectedly changed")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var value map[string]any
			decoder := json.NewDecoder(bytes.NewReader(baseline))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			for _, change := range c.Changes {
				parts := strings.Split(change.Path, ".")
				var node any = value
				for _, key := range parts[:len(parts)-1] {
					if array, ok := node.([]any); ok {
						i, err := strconv.Atoi(key)
						if err != nil {
							t.Fatal(err)
						}
						node = array[i]
					} else {
						node = node.(map[string]any)[key]
					}
				}
				last := parts[len(parts)-1]
				if array, ok := node.([]any); ok {
					i, err := strconv.Atoi(last)
					if err != nil {
						t.Fatal(err)
					}
					array[i] = change.Value
				} else {
					node.(map[string]any)[last] = change.Value
				}
			}
			// Valid digest on every changed plan distinguishes semantic refusal.
			digest, err := storagePlanDigest(value["plan"])
			if err != nil {
				t.Fatal(err)
			}
			value["plan_sha256"] = digest
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeStorageTransaction(body)
			if (err == nil) != c.Accepted {
				t.Fatalf("semantic admission differs: accepted=%v error=%v", c.Accepted, err)
			}
		})
	}
}

func TestStorageDigestPythonVectors(t *testing.T) {
	body, err := os.ReadFile("../../contracts/storage_digest_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var vectors []struct {
		Value  any    `json:"value"`
		SHA256 string `json:"sha256"`
	}
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 3 {
		t.Fatal("missing digest controls")
	}
	for _, vector := range vectors {
		got, err := storagePlanDigest(vector.Value)
		if err != nil || got != vector.SHA256 {
			t.Fatalf("cross-language canonical digest mismatch: %v", err)
		}
	}
	for _, invalid := range []any{float64(1), json.Number("1.0"), json.Number("9223372036854775808"), true} {
		if _, err := storagePlanDigest(invalid); err == nil {
			t.Fatal("accepted unsupported canonical value")
		}
	}
	zero, _ := storagePlanDigest(json.Number("0"))
	negativeZero, _ := storagePlanDigest(json.Number("-0"))
	if zero != negativeZero {
		t.Fatal("negative zero differs from Python integer canonicalization")
	}
}

func TestStorageUnicodeAdmission(t *testing.T) {
	for _, body := range []string{`"\ud83d\ude00"`, `"\\ud800"`, `"שלום"`, `"\ufffd"`} {
		if !storageUnicode([]byte(body)) {
			t.Fatal("refused valid Unicode encoding")
		}
	}
	for _, body := range []string{`"\ud800"`, `"\udc00"`, `"\ud800\u0041"`, `"\ud800x"`, "\xff"} {
		if storageUnicode([]byte(body)) {
			t.Fatal("accepted lossy Unicode encoding")
		}
	}
}
