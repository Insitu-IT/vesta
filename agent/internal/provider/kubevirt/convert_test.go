package kubevirt

import "testing"

func TestParseMemoryToKB(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1Gi", 1024 * 1024},
		{"512Mi", 512 * 1024},
		{"2048Ki", 2048},
		{"2G", 1953125},
		{"500M", 488282},
		{"1Ti", 1024 * 1024 * 1024},
		{"1.5Gi", 1572864},
		{"1.5G", 1464844},
		{"1024", 1},
		{"1025", 2},
		{"1e6", 977},
		{"1m", 1},
		{"-1Gi", 0},
		{"999999999999999999999999999999Gi", 0},
		{"1e30", 0},
		{"12MiB", 0},
		{"", 0},
		{"  ", 0},
		{"garbage", 0},
		{"0Gi", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMemoryToKB(tt.input)
			if got != tt.expected {
				t.Errorf("parseMemoryToKB(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapPhaseToState(t *testing.T) {
	tests := []struct {
		phase    string
		expected string
	}{
		{"Running", "running"},
		{"running", "running"},
		{"Scheduling", "pending"},
		{"Scheduled", "pending"},
		{"Pending", "pending"},
		{"Succeeded", "shutoff"},
		{"Failed", "shutoff"},
		{"Paused", "paused"},
		{"", "unknown"},
		{"SomeFuturePhase", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			got := mapPhaseToState(tt.phase)
			if got != tt.expected {
				t.Errorf("mapPhaseToState(%q) = %q, want %q", tt.phase, got, tt.expected)
			}
		})
	}
}

func TestPhaseToEventType(t *testing.T) {
	tests := []struct {
		phase    string
		expected string
	}{
		{"running", "vm_started"},
		{"Running", "vm_started"},
		{"succeeded", "vm_stopped"},
		{"failed", "vm_stopped"},
		{"paused", "vm_paused"},
		{"scheduling", ""},
		{"pending", ""},
		{"", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			got := phaseToEventType(tt.phase)
			if got != tt.expected {
				t.Errorf("phaseToEventType(%q) = %q, want %q", tt.phase, got, tt.expected)
			}
		})
	}
}
