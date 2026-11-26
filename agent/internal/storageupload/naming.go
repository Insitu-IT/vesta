package storageupload

import "vnbui/agent/internal/config"

// CreateWithKubevirtPrefix pins naming in the first durable record, before any
// native effects. Reopened journals never adopt the current process prefix.
func CreateWithKubevirtPrefix(root string, request []byte, prefix string) (*Journal, error) {
	normalized, err := config.NormalizeKubevirtResourcePrefix(prefix)
	if err != nil {
		return nil, ErrHeld
	}
	return create(root, request, normalized)
}
