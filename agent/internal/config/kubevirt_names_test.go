package config

import "testing"

func TestKubevirtResourcePrefixExplicitAndLegacy(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"", "vnbui"}, {"vnbui", "vnbui"}, {"vesta", "vesta"}} {
		t.Run(tc.want+tc.input, func(t *testing.T) {
			t.Setenv("KUBEVIRT_RESOURCE_PREFIX", tc.input)
			c := Load()
			if c.KubevirtPrefix() != tc.want {
				t.Fatal(c.KubevirtPrefix())
			}
		})
	}
	for _, prefix := range []string{"Vesta", "other", "vesta-", " vesta", "vesta/other"} {
		c := &Config{KubevirtResourcePrefix: prefix}
		if c.KubevirtPrefix() != "" || c.ValidateProduction() == nil {
			t.Fatal("invalid prefix accepted", prefix)
		}
	}
	if (&Config{}).KubevirtPrefix() != "vnbui" {
		t.Fatal("zero config lost legacy naming")
	}
}
