package models

import (
	"encoding/json"
	"os"
	"testing"
)

// Receipt schema/hash compatibility with immutable C01 examples is distinct
// from admission of their pre-D02 request envelope. No legacy plan is adopted.
func TestStorageReceiptC01Golden(t *testing.T) {
	for _, name := range []string{"1-disk", "2-disk", "incremental", "libvirt"} {
		t.Run(name, func(t *testing.T) {
			data, e := os.ReadFile("../../../tests/fixtures/storage-contract-v1/" + name + ".json")
			if e != nil {
				t.Fatal(e)
			}
			var fixture struct {
				Request    StorageTransactionRequest `json:"request"`
				Receipt    StorageReceipt            `json:"prepared_receipt"`
				Acceptance StorageAcceptance         `json:"acceptance"`
			}
			if e = json.Unmarshal(data, &fixture); e != nil {
				t.Fatal(e)
			}
			body, hash, e := CanonicalReceipt(&fixture.Request, fixture.Receipt)
			if e != nil || hash != fixture.Acceptance.ReceiptSHA256 {
				t.Fatal("C01 receipt hash drift", e)
			}
			var decoded StorageReceipt
			if e = DecodeStorageValue(body, &decoded, MaxStorageReceiptBytes); e != nil {
				t.Fatal(e)
			}
			body, _ = json.Marshal(fixture.Acceptance)
			if _, e = DecodeStorageAcceptance(body, &fixture.Request, decoded); e != nil {
				t.Fatal(e)
			}
		})
	}
}
