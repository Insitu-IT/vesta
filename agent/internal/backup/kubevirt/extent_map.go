//go:build kubevirt

package kubevirt

import (
	"fmt"
	"math"
	"strings"
)

type mapExtent struct {
	Offset      uint64 `json:"offset"`
	Length      uint64 `json:"length"`
	Type        uint64 `json:"type"`
	Description string `json:"description"`
}

type storedExtent struct {
	DiskOffset    uint64  `json:"disk_offset"`
	Length        uint64  `json:"length"`
	PayloadOffset *uint64 `json:"payload_offset,omitempty"`
	ZeroFill      bool    `json:"zero_fill,omitempty"`
}

func storedExtents(extents []mapExtent, backupType string) ([]storedExtent, error) {
	stored := make([]storedExtent, 0, len(extents))
	var payloadOffset uint64
	incremental := strings.EqualFold(backupType, "Incremental")
	if !incremental && !strings.EqualFold(backupType, "Full") {
		return nil, fmt.Errorf("unsupported extent-map backup type %q", backupType)
	}
	for _, extent := range extents {
		if extent.Length == 0 {
			continue
		}
		if extent.Length > math.MaxInt64 {
			return nil, fmt.Errorf("extent length %d at offset %d exceeds supported range", extent.Length, extent.Offset)
		}
		description := strings.ToLower(strings.TrimSpace(extent.Description))
		if incremental {
			switch description {
			case "clean":
				// Full allocation descriptions cannot prove bitmap cleanliness.
				continue
			case "dirty":
				offset := payloadOffset
				stored = append(stored, storedExtent{DiskOffset: extent.Offset, Length: extent.Length, PayloadOffset: &offset})
				payloadOffset += extent.Length
			case "dirty,zero":
				stored = append(stored, storedExtent{DiskOffset: extent.Offset, Length: extent.Length, ZeroFill: true})
			default:
				return nil, fmt.Errorf("unknown incremental extent description %q at offset %d", extent.Description, extent.Offset)
			}
			continue
		}
		switch description {
		case "hole", "zero", "hole,zero":
			// These full-map ranges are absent from the payload, not unknown data.
			continue
		case "data":
			offset := payloadOffset
			stored = append(stored, storedExtent{DiskOffset: extent.Offset, Length: extent.Length, PayloadOffset: &offset})
			payloadOffset += extent.Length
		default:
			return nil, fmt.Errorf("unknown full extent description %q at offset %d", extent.Description, extent.Offset)
		}
	}
	return stored, nil
}
