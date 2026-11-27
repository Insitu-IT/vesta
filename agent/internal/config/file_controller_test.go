package config

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestFileControllerRotationAndExpiry(t *testing.T) {
	cfg := new(Config)
	for _, leaf := range []string{"first", "second"} {
		sum := sha256.Sum256([]byte(leaf))
		cfg.ObserveControllers("", hex.EncodeToString(sum[:]))
		if ready, match := cfg.ControllerPeer(FileController, []byte(leaf)); !ready || !match {
			t.Fatal("current controller refused")
		}
		if _, match := cfg.ControllerPeer(FileController, []byte("peer agent")); match {
			t.Fatal("unrelated client accepted")
		}
	}
	if _, match := cfg.ControllerPeer(FileController, []byte("first")); match {
		t.Fatal("retired cert accepted")
	}
	cfg.fileController.until = time.Now().Add(-time.Second)
	if ready, _ := cfg.ControllerPeer(FileController, []byte("second")); ready {
		t.Fatal("expired heartbeat pin accepted")
	}
	cfg.ObserveControllers("", "not a digest")
	if ready, _ := cfg.ControllerPeer(FileController, nil); ready {
		t.Fatal("invalid control identity accepted")
	}
}
