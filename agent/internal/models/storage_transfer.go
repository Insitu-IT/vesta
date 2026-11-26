package models

// StorageSourceRangeBytes is derived only from the immutable admitted plan.
// Export readers remain lazy and never read beyond the current mapped extent.
func StorageSourceRangeBytes(profile string) (uint64, error) {
	switch profile {
	case "":
		return 8 << 20, nil
	case KubevirtTransfer32:
		return 32 << 20, nil
	default:
		return 0, ErrStorageRequest
	}
}
