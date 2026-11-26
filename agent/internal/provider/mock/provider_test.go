package mock

import (
	"testing"

	"vnbui/agent/internal/provider"
)

func TestMockProvider(t *testing.T) {
	p := New()

	if p.IsConnected() {
		t.Error("should not be connected before Connect()")
	}

	if err := p.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !p.IsConnected() {
		t.Error("should be connected after Connect()")
	}

	vms, err := p.ListVMs()
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 4 {
		t.Errorf("expected 4 VMs, got %d", len(vms))
	}

	vm, err := p.GetVM("mock-vm-01")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.Name != "mock-vm-01" {
		t.Errorf("expected mock-vm-01, got %s", vm.Name)
	}
	if vm.State != "running" {
		t.Errorf("expected running, got %s", vm.State)
	}

	_, err = p.GetVM("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent VM")
	}

	progress, _ := p.GetBlockJobProgress("mock-vm-01")
	if progress != nil {
		t.Error("expected nil block job progress")
	}

	caps := p.Capabilities()
	if !caps.SupportsIncremental {
		t.Error("mock should support incremental")
	}
	if caps.BackupMethod != "virtnbdbackup" {
		t.Errorf("expected virtnbdbackup, got %s", caps.BackupMethod)
	}

	p.Disconnect()
	if p.IsConnected() {
		t.Error("should not be connected after Disconnect()")
	}
}

func TestMockProviderEvents(t *testing.T) {
	p := New()
	p.Connect()

	received := make(chan provider.VMEvent, 1)
	p.SubscribeEvents(func(evt provider.VMEvent) {
		received <- evt
	})

	p.EmitEvent(provider.VMEvent{
		Type:   provider.EventVMStarted,
		VMName: "test-vm",
	})

	evt := <-received
	if evt.Type != provider.EventVMStarted {
		t.Errorf("expected vm_started, got %s", evt.Type)
	}

	p.UnsubscribeEvents()
}

func TestMockProviderEventsFieldValues(t *testing.T) {
	p := New()
	p.Connect()

	received := make(chan provider.VMEvent, 1)
	p.SubscribeEvents(func(evt provider.VMEvent) {
		received <- evt
	})

	// Test all event types
	tests := []struct {
		evtType provider.EventType
		vmName  string
		detail  string
	}{
		{provider.EventVMStarted, "vm1", "booted"},
		{provider.EventVMStopped, "vm2", "shutdown"},
		{provider.EventVMCrashed, "vm3", "crash"},
		{provider.EventBlockJob, "vm4", "disk=vda status=1"},
	}

	for _, tt := range tests {
		p.EmitEvent(provider.VMEvent{
			Type:   tt.evtType,
			VMName: tt.vmName,
			Detail: tt.detail,
		})

		evt := <-received
		if evt.Type != tt.evtType {
			t.Errorf("Type = %q, want %q", evt.Type, tt.evtType)
		}
		if evt.VMName != tt.vmName {
			t.Errorf("VMName = %q, want %q", evt.VMName, tt.vmName)
		}
		if evt.Detail != tt.detail {
			t.Errorf("Detail = %q, want %q", evt.Detail, tt.detail)
		}
	}

	p.UnsubscribeEvents()
}

func TestMockProviderEventsAfterUnsubscribe(t *testing.T) {
	p := New()
	p.Connect()

	callCount := 0
	p.SubscribeEvents(func(evt provider.VMEvent) {
		callCount++
	})

	p.EmitEvent(provider.VMEvent{Type: provider.EventVMStarted, VMName: "vm1"})
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	p.UnsubscribeEvents()
	p.EmitEvent(provider.VMEvent{Type: provider.EventVMStarted, VMName: "vm2"})
	if callCount != 1 {
		t.Errorf("callCount = %d after unsubscribe, want 1 (no change)", callCount)
	}
}

func TestMockProviderDisconnected(t *testing.T) {
	p := New()

	_, err := p.ListVMs()
	if err == nil {
		t.Error("ListVMs should fail when disconnected")
	}

	_, err = p.GetVM("test")
	if err == nil {
		t.Error("GetVM should fail when disconnected")
	}
}
