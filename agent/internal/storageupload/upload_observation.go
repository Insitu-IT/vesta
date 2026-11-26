package storageupload

import "math"

// UploadProgress describes payload bytes on the wire (including encryption
// framing), not disk capacity or publication. Manifests are excluded. Extent
// maps supply the denominator so sparse/incremental disks are not divided by
// their full provisioned capacity. Unacknowledged PendingPart never counts.
type UploadProgress struct {
	BytesTransferred int64
	TotalBytes       int64
}

func payloadProgress(s *State) UploadProgress {
	var p UploadProgress
	for _, m := range s.Maps {
		var bytes int64
		for _, r := range m.Ranges {
			if !r.ZeroFill {
				if r.Length > math.MaxInt64 || bytes > math.MaxInt64-int64(r.Length) {
					return UploadProgress{}
				}
				bytes += int64(r.Length)
			}
		}
		if s.Request.Plan.Encryption.Format != "none" {
			frames := bytes / 5242880
			if bytes%5242880 != 0 {
				frames++
			}
			overhead := 5 + 32*frames
			if bytes > math.MaxInt64-overhead {
				return UploadProgress{}
			}
			bytes += overhead
		}
		if p.TotalBytes > math.MaxInt64-bytes {
			return UploadProgress{}
		}
		p.TotalBytes += bytes
	}
	for _, o := range s.Objects {
		if o.Artifact.Role != "volume_payload" {
			continue
		}
		for _, part := range o.Parts {
			p.BytesTransferred += part.Bytes
		}
	}
	return p
}
