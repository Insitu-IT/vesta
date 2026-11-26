package backup

import "testing"

func TestCalculatePartSize(t *testing.T) {
	tests := []struct {
		name     string
		fileSize int64
		wantMin  int64
		wantMax  int64
	}{
		{"small file 100MB", 100 * 1024 * 1024, defaultPartSize, defaultPartSize},
		{"200GB", 200 * 1024 * 1024 * 1024, defaultPartSize, defaultPartSize},
		{"1TB", 1024 * 1024 * 1024 * 1024, defaultPartSize, defaultPartSize},
		{"1.5TB needs scale-up", 1536 * 1024 * 1024 * 1024, defaultPartSize + 1, maxPartSize},
		{"5TB", 5 * 1024 * 1024 * 1024 * 1024, defaultPartSize + 1, maxPartSize},
		{"tiny file 1MB", 1024 * 1024, minPartSize, defaultPartSize},
		{"zero", 0, minPartSize, defaultPartSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePartSize(tt.fileSize)

			if got < tt.wantMin {
				t.Errorf("CalculatePartSize(%d) = %d, want >= %d", tt.fileSize, got, tt.wantMin)
			}
			if got > tt.wantMax {
				t.Errorf("CalculatePartSize(%d) = %d, want <= %d", tt.fileSize, got, tt.wantMax)
			}

			// Verify we don't exceed max parts
			if tt.fileSize > 0 {
				parts := (tt.fileSize + got - 1) / got
				if parts > maxParts {
					t.Errorf("CalculatePartSize(%d) = %d gives %d parts (max %d)", tt.fileSize, got, parts, maxParts)
				}
			}

			// Verify minimum
			if got < minPartSize {
				t.Errorf("CalculatePartSize(%d) = %d, below S3 minimum %d", tt.fileSize, got, minPartSize)
			}
		})
	}
}

func TestCalculatePartSizeEdgeCases(t *testing.T) {
	// At exactly the boundary: 10000 * 128MB = 1.28TB
	boundary := int64(maxParts) * defaultPartSize
	got := CalculatePartSize(boundary)
	parts := (boundary + got - 1) / got
	if parts > maxParts {
		t.Errorf("at boundary %d: part_size=%d gives %d parts", boundary, got, parts)
	}

	// Just over the boundary
	got = CalculatePartSize(boundary + 1)
	parts = (boundary + 1 + got - 1) / got
	if parts > maxParts {
		t.Errorf("over boundary %d: part_size=%d gives %d parts", boundary+1, got, parts)
	}
}
