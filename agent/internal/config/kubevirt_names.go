package config

import "fmt"

// NormalizeKubevirtResourcePrefix preserves installations and journals predating
// explicit Kubernetes naming. Never derive names from a namespace or edition.
func NormalizeKubevirtResourcePrefix(prefix string) (string, error) {
	switch prefix {
	case "", "vnbui":
		return "vnbui", nil
	case "vesta":
		return "vesta", nil
	default:
		return "", fmt.Errorf("KUBEVIRT_RESOURCE_PREFIX must be vnbui or vesta")
	}
}

func (c *Config) KubevirtPrefix() string {
	if c == nil {
		return "vnbui"
	}
	prefix, _ := NormalizeKubevirtResourcePrefix(c.KubevirtResourcePrefix)
	return prefix
}
