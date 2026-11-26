//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/models"
)

func TestCredentialCleanupFailureReopensWithoutAnotherWriter(t *testing.T) {
	e, state, client := controllerFixture(t)
	ctx := context.Background()
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	completeWorker(t, state, client)
	fail := true
	client.PrependReactor("delete", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		uid := action.(ktesting.DeleteAction).GetDeleteOptions().Preconditions.UID
		if uid == nil || string(*uid) != state.SecretUID {
			t.Fatal("cleanup lost its original UID precondition")
		}
		if fail {
			return true, nil, apierrors.NewServiceUnavailable("injected cleanup outage")
		}
		return false, nil, nil
	})
	if err := e.reconcile(ctx, state); err == nil {
		t.Fatal("credential deletion failure was ignored")
	}
	if state.Phase != "credential_cleanup" || state.Progress.Status != models.TaskStatusRunning || state.Progress.ProgressPercent != 99 || state.VMUID == "" {
		t.Fatal("cleanup failure reported completion or lost destination identity")
	}
	data, err := os.ReadFile(filepath.Join(e.root, state.Request.RestoreID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var reopened restoreState
	if err := json.Unmarshal(data, &reopened); err != nil {
		t.Fatal(err)
	}
	if reopened.Phase != state.Phase || reopened.Request.S3.SecretKey == "" || reopened.JobUID != state.JobUID || reopened.VMUID != state.VMUID {
		t.Fatal("pending cleanup was not durable")
	}
	if _, digest, err := validatePlan(&reopened.Request, true); err != nil || digest != state.PlanSHA {
		t.Fatal("pending cleanup cannot pass startup validation", err)
	}
	client.ClearActions()
	fail = false
	if err := e.reconcile(ctx, &reopened); err != nil {
		t.Fatal(err)
	}
	if reopened.Progress.Status != models.TaskStatusCompleted || reopened.Request.S3.SecretKey != "" || reopened.Request.Keys != nil {
		t.Fatal("cleanup did not finalize and redact credentials")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && !(action.GetVerb() == "delete" && action.GetResource() == secretGVR) {
			t.Fatal("cleanup retried a destination writer", action)
		}
	}
	if _, err := client.Resource(secretGVR).Namespace("ns").Get(ctx, resourceName(state), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("credential Secret survived successful cleanup", err)
	}
}

func TestCredentialCleanupNeverDeletesReplacementSecret(t *testing.T) {
	e, state, client := controllerFixture(t)
	ctx := context.Background()
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	completeWorker(t, state, client)
	client.PrependReactor("delete", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("injected cleanup outage")
	})
	if err := e.reconcile(ctx, state); err == nil {
		t.Fatal("cleanup outage ignored")
	}
	secret, err := client.Resource(secretGVR).Namespace("ns").Get(ctx, resourceName(state), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.SetUID("replacement-secret")
	if _, err := client.Resource(secretGVR).Namespace("ns").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	if err := e.reconcile(ctx, state); !errors.Is(err, errHeld) {
		t.Fatal("replacement Secret did not hold cleanup", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("replacement cleanup caused a mutation", action)
		}
	}
}

func TestCredentialCleanupLostDeleteResponseOnlyObservesAbsence(t *testing.T) {
	e, state, client := controllerFixture(t)
	ctx := context.Background()
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	completeWorker(t, state, client)
	client.PrependReactor("delete", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if err := client.Tracker().Delete(secretGVR, action.GetNamespace(), action.(ktesting.DeleteAction).GetName()); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewServiceUnavailable("injected lost deletion response")
	})
	if err := e.reconcile(ctx, state); err == nil || state.Phase != "credential_cleanup" {
		t.Fatal("lost deletion response was reported as completion", err)
	}
	client.ClearActions()
	if err := e.reconcile(ctx, state); err != nil || state.Progress.Status != models.TaskStatusCompleted {
		t.Fatal("absent original credential Secret did not complete cleanup", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" || action.GetResource() != secretGVR {
			t.Fatal("lost-response retry did more than observe credential absence", action)
		}
	}
}
