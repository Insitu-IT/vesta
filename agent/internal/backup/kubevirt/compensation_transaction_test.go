//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func TestProductionPreFinalizePositiveLossCompensatesSameIntentOnly(t *testing.T) {
	f := readyExportFixture(t, false, true, 9)
	f.versioned = true
	original := f.backend.Transport
	calls := 0
	absent := false
	loseAck := true
	f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/prepared-receipt") {
			resp, err := original.RoundTrip(req)
			s := f.disk(t)
			d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
			if deleteErr := d.Tracker().Delete(kvtypes.BackupTrackerResource, s.Request.Plan.Source.Namespace, s.Native.Objects[0].Name); deleteErr != nil {
				t.Fatal(deleteErr)
			}
			return resp, err
		}
		if strings.HasSuffix(req.URL.Path, "/storage-control") && f.disk(t).Compensation != nil {
			s := f.disk(t)
			if s.Finalize != nil || s.Phase != "compensating" {
				t.Fatal("effect before abort durability")
			}
			var value map[string]any
			if json.NewDecoder(req.Body).Decode(&value) != nil || value["operation"] != "compensate_pre_finalize" || value["artifact_key"] != "" {
				t.Fatal("wrong cleanup control")
			}
			calls++
			if loseAck {
				loseAck = false
				return nil, io.ErrUnexpectedEOF
			}
			return exportResponse(map[string]any{"schema": 1, "intent_id": s.Compensation.AbortID, "s3_absent": absent, "cleanup_required": true, "capacity_state": "reserved"}), nil
		}
		if strings.HasSuffix(req.URL.Path, "/finalize-intent") || strings.HasSuffix(req.URL.Path, "/checkpoint-proof") {
			t.Fatal("aborted producer finalized")
		}
		return original.RoundTrip(req)
	})
	run := func() {
		t.Helper()
		proof, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
		if err == nil || proof != nil {
			t.Fatal("cleanup became completion")
		}
	}
	run()
	streams := f.streams
	if calls != 1 || f.disk(t).Compensation == nil {
		t.Fatal("positive original loss not compensated")
	}
	run()
	if calls != 2 || f.disk(t).Phase != "compensating" {
		t.Fatal("denial stopped retry")
	}
	absent = true
	run()
	s := f.disk(t)
	if calls != 3 || s.Phase != "held" || !s.Compensation.S3Absent || s.Finalize != nil || f.streams != streams {
		t.Fatal("receipt replay/native hold")
	}
	run()
	if calls != 3 || f.streams != streams {
		t.Fatal("settled S3 replay did effects")
	}
}

func TestProductionPreFinalizeAPIUncertaintyDoesNotAuthorizeCompensation(t *testing.T) {
	f := readyExportFixture(t, false, false, 9)
	f.versioned = true
	if _, err := f.e.AcceptStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil }); err != nil {
		t.Fatal(err)
	}
	f.e.dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("get", "virtualmachinebackuptrackers", func(k8stest.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("temporary API uncertainty")
	})
	proof, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
	if err == nil || proof != nil || f.disk(t).Compensation != nil {
		t.Fatal("uncertain API authorized abort")
	}
}
