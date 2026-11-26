package security

import "testing"

func TestValidateVMName(t *testing.T) {
	valid := []string{"my-vm", "vm01", "test.vm", "vm_name", "VM-01"}
	for _, name := range valid {
		if err := ValidateVMName(name); err != nil {
			t.Errorf("ValidateVMName(%q) should be valid: %v", name, err)
		}
	}

	invalid := []string{"", "../etc/passwd", "vm name", "vm;rm -rf", "vm\nname", "/vm"}
	for _, name := range invalid {
		if err := ValidateVMName(name); err == nil {
			t.Errorf("ValidateVMName(%q) should be invalid", name)
		}
	}
}

func TestValidateDiskName(t *testing.T) {
	valid := []string{"vda", "sda", "vdb1", "nvme0n1"}
	for _, name := range valid {
		if err := ValidateDiskName(name); err != nil {
			t.Errorf("ValidateDiskName(%q) should be valid: %v", name, err)
		}
	}

	invalid := []string{"", "../vda", "vda;cmd"}
	for _, name := range invalid {
		if err := ValidateDiskName(name); err == nil {
			t.Errorf("ValidateDiskName(%q) should be invalid", name)
		}
	}
}

func TestValidatePath(t *testing.T) {
	valid := []string{"/var/lib/vnbui/backups", "/tmp/test"}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) should be valid: %v", p, err)
		}
	}

	invalid := []string{"", "relative/path", "/var/lib/../../../etc/passwd"}
	for _, p := range invalid {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) should be invalid", p)
		}
	}
}

func TestValidateCompression(t *testing.T) {
	for _, c := range []string{"", "1", "5", "9"} {
		if err := ValidateCompression(c); err != nil {
			t.Errorf("ValidateCompression(%q) should be valid: %v", c, err)
		}
	}

	for _, c := range []string{"0", "10", "abc"} {
		if err := ValidateCompression(c); err == nil {
			t.Errorf("ValidateCompression(%q) should be invalid", c)
		}
	}
}

func TestValidateWorkers(t *testing.T) {
	for _, w := range []int{1, 4, 8} {
		if err := ValidateWorkers(w); err != nil {
			t.Errorf("ValidateWorkers(%d) should be valid: %v", w, err)
		}
	}

	for _, w := range []int{0, -1, 9, 100} {
		if err := ValidateWorkers(w); err == nil {
			t.Errorf("ValidateWorkers(%d) should be invalid", w)
		}
	}
}

func TestValidateCheckpointName(t *testing.T) {
	// Empty is OK (optional)
	if err := ValidateCheckpointName(""); err != nil {
		t.Errorf("empty checkpoint should be valid: %v", err)
	}

	if err := ValidateCheckpointName("cp-2026-03-09"); err != nil {
		t.Errorf("valid checkpoint rejected: %v", err)
	}

	if err := ValidateCheckpointName("../evil"); err == nil {
		t.Error("traversal checkpoint should be invalid")
	}
}
