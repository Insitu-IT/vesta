package models

import "testing"

func TestStorageUnsignedJournalExtentCodec(t *testing.T) {
	for _, n := range []string{"0", "1", "18446744073709551615", "-1", "18446744073709551616", "1.0", "1e2", "true", "null", `"1"`} {
		var v struct {
			Value uint64 `json:"value"`
		}
		err := DecodeStorageValue([]byte(`{"value":`+n+`}`), &v, 100)
		valid := n == "0" || n == "1" || n == "18446744073709551615"
		if (err == nil) != valid {
			t.Fatalf("unsigned representation %s", n)
		}
	}
}
