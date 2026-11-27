package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"
)

// ControllerRole selects the pin corresponding to the requested workload.
type ControllerRole uint8

const (
	VMController ControllerRole = iota
	FileController
	EitherController
)

type controllerPin struct {
	fingerprint [sha256.Size]byte
	until       time.Time
}

func newControllerPin(fingerprint string, until time.Time) controllerPin {
	raw, err := hex.DecodeString(fingerprint)
	if err != nil || len(raw) != sha256.Size {
		return controllerPin{}
	}
	return controllerPin{fingerprint: [sha256.Size]byte(raw), until: until}
}

// ObserveControllers replaces both leases after a verified heartbeat for this
// agent. Missing or invalid values revoke the corresponding lease immediately.
func (c *Config) ObserveControllers(vm, files string) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	interval := max(30, min(c.HeartbeatInterval, 300))
	until := time.Now().Add(time.Duration(3*interval) * time.Second)
	c.vmController = newControllerPin(vm, until)
	c.fileController = newControllerPin(files, until)
}

// ControllerPeer checks the current workload pin against the verified TLS leaf.
func (c *Config) ControllerPeer(role ControllerRole, leaf []byte) (ready, matches bool) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	now := time.Now()
	digest := sha256.Sum256(leaf)
	for _, entry := range []struct {
		role ControllerRole
		pin  controllerPin
	}{{VMController, c.vmController}, {FileController, c.fileController}} {
		if (role != EitherController && role != entry.role) || !now.Before(entry.pin.until) {
			continue
		}
		ready = true
		matches = matches || len(leaf) > 0 && subtle.ConstantTimeCompare(digest[:], entry.pin.fingerprint[:]) == 1
	}
	return ready, matches
}
