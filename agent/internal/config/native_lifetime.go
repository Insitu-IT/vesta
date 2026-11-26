package config

import "fmt"

const (
	// Leave headroom below HCO's observed 12h exporter certificate rotation
	// window (24h duration minus 12h renewal). Actual deadlines remain checked.
	DefaultNativeBackupTTLSeconds = 10 * 3600
	MinNativeBackupTTLSeconds     = 3600
	MaxNativeBackupTTLSeconds     = 30 * 24 * 3600
)

func (c *Config) ValidateNativeLifetime() error {
	if c.KubevirtNativeTTLSeconds < MinNativeBackupTTLSeconds || c.KubevirtNativeTTLSeconds > MaxNativeBackupTTLSeconds {
		return fmt.Errorf("KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS must be 3600..2592000")
	}
	if c.KubevirtTransactionTimeoutSeconds < 0 || c.KubevirtTransactionTimeoutSeconds > c.KubevirtNativeTTLSeconds {
		return fmt.Errorf("KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS must be 0..KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS (0 disables only the additional runner deadline)")
	}
	return nil
}
