//go:build libvirt

package libvirt

import (
	"errors"
	"reflect"
	"testing"

	lv "libvirt.org/go/libvirt"
	"vnbui/agent/internal/provider"
)

func TestConnectionRegistersEventsBeforeOpening(t *testing.T) {
	var calls []string
	want := errors.New("connection probe")
	_, err := connectWithEvents("test:///default", func() error {
		calls = append(calls, "events")
		return nil
	}, func(uri string) (*lv.Connect, error) {
		if uri != "test:///default" {
			t.Fatalf("unexpected URI %q", uri)
		}
		calls = append(calls, "connect")
		return nil, want
	})
	if !errors.Is(err, want) || !reflect.DeepEqual(calls, []string{"events", "connect"}) {
		t.Fatalf("event/connection order = %v, error = %v", calls, err)
	}
}

func TestEventInitializationFailureDoesNotOpenConnection(t *testing.T) {
	want := errors.New("event initialization failed")
	opened := false
	_, err := connectWithEvents("test:///default", func() error { return want }, func(string) (*lv.Connect, error) {
		opened = true
		return nil, nil
	})
	if opened || !errors.Is(err, want) {
		t.Fatal("failed event initialization opened a connection")
	}
}

func TestLifecycleEventsIncludeStoppedInventoryChanges(t *testing.T) {
	for _, test := range []struct {
		event  lv.DomainEventType
		kind   provider.EventType
		detail string
	}{
		{lv.DOMAIN_EVENT_DEFINED, provider.EventInventoryChanged, "defined"},
		{lv.DOMAIN_EVENT_UNDEFINED, provider.EventInventoryChanged, "undefined"},
		{lv.DOMAIN_EVENT_STARTED, provider.EventVMStarted, "started"},
		{lv.DOMAIN_EVENT_STOPPED, provider.EventVMStopped, "stopped"},
		{lv.DOMAIN_EVENT_SHUTDOWN, provider.EventVMStopped, "shutdown"},
		{lv.DOMAIN_EVENT_CRASHED, provider.EventVMCrashed, "crashed"},
		{lv.DOMAIN_EVENT_SUSPENDED, provider.EventVMPaused, "paused"},
		{lv.DOMAIN_EVENT_RESUMED, provider.EventVMResumed, "resumed"},
	} {
		kind, detail, relevant := lifecycleEvent(test.event)
		if !relevant || kind != test.kind || detail != test.detail {
			t.Fatalf("event %d: %q %q relevant=%v", test.event, kind, detail, relevant)
		}
	}
	if _, _, relevant := lifecycleEvent(lv.DomainEventType(999)); relevant {
		t.Fatal("unknown lifecycle event became an inventory signal")
	}
}
