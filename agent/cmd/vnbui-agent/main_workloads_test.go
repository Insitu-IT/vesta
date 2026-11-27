package main

import (
	"errors"
	"testing"

	"vnbui/agent/internal/provider"
)

type connectionProbe struct {
	provider.VMProvider
	err          error
	disconnected bool
}

func (p *connectionProbe) Connect() error { return p.err }

func (p *connectionProbe) Disconnect() { p.disconnected = true }

func TestMixedAgentKeepsFilesWhenLibvirtIsUnavailable(t *testing.T) {
	unavailable := errors.New("libvirt unavailable")
	probe := &connectionProbe{err: unavailable}
	if p, err := connectVMProvider(probe, true); err != nil || p != nil || !probe.disconnected {
		t.Fatalf("mixed startup: provider=%v error=%v closed=%t", p, err, probe.disconnected)
	}
	if p, err := connectVMProvider(&connectionProbe{err: unavailable}, false); p != nil || !errors.Is(err, unavailable) {
		t.Fatalf("VM-only startup: provider=%v error=%v", p, err)
	}
	probe = &connectionProbe{}
	if p, err := connectVMProvider(probe, true); err != nil || p != probe {
		t.Fatalf("healthy mixed startup: provider=%v error=%v", p, err)
	}
}
