package config

import "testing"

func TestNativeLifetimeBoundsAndRelation(t *testing.T) {
	for _, tc := range []struct {
		ttl, transaction int
		valid            bool
	}{
		{64800, 0, true}, {3600, 3600, true}, {2592000, 2592000, true},
		{0, 0, false}, {3599, 0, false}, {2592001, 0, false}, {64800, -1, false}, {64800, 64801, false},
	} {
		c := &Config{KubevirtNativeTTLSeconds: tc.ttl, KubevirtTransactionTimeoutSeconds: tc.transaction}
		if (c.ValidateNativeLifetime() == nil) != tc.valid {
			t.Fatalf("policy %+v", tc)
		}
	}
}
