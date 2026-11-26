package restore

import (
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

func TestBuildCommandStartsWithSudo(t *testing.T) {
	cfg := &config.Config{
		VirtnbdrestorePath: "/usr/bin/virtnbdrestore",
		LibvirtURI:         "qemu:///system",
	}

	req := &models.RestoreRequest{
		RestoreID:   "r-001",
		RestorePath: "/var/lib/libvirt/images",
		Action:      "restore",
	}

	args, err := BuildCommand(cfg, req.RestorePath, req, "/backups/r-001")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	if args[0] != "sudo" {
		t.Errorf("args[0] = %q, want \"sudo\"", args[0])
	}
	if args[1] != "/usr/bin/virtnbdrestore" {
		t.Errorf("args[1] = %q, want virtnbdrestore path", args[1])
	}
}

func TestBuildCommandVerifyAction(t *testing.T) {
	cfg := &config.Config{
		VirtnbdrestorePath: "/usr/bin/virtnbdrestore",
		LibvirtURI:         "qemu:///system",
	}

	req := &models.RestoreRequest{
		RestoreID: "r-002",
		Action:    "verify",
	}

	args, err := BuildCommand(cfg, "", req, "/backups/r-002")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	// Should have -o verify
	found := false
	for i, a := range args {
		if a == "-o" && i+1 < len(args) && args[i+1] == "verify" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing -o verify for verify action")
	}
}

func TestBuildCommandSelectedDisks(t *testing.T) {
	cfg := &config.Config{
		VirtnbdrestorePath: "/usr/bin/virtnbdrestore",
		LibvirtURI:         "qemu:///system",
	}

	req := &models.RestoreRequest{
		RestoreID:     "r-003",
		RestorePath:   "/var/lib/libvirt/images",
		Action:        "restore",
		SelectedDisks: []string{"vda"},
	}

	args, err := BuildCommand(cfg, req.RestorePath, req, "/backups/r-003")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	// Should have -d vda
	found := false
	for i, a := range args {
		if a == "-d" && i+1 < len(args) && args[i+1] == "vda" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing -d vda for selected disk")
	}
}
