//go:build kubevirt

package reconcile

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/config"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

type noTransactionIO struct{ t *testing.T }

func (n noTransactionIO) RoundTrip(*http.Request) (*http.Response, error) {
	n.t.Fatal("held restart performed HTTP")
	return nil, nil
}

func TestCurrentTransactionRestartCannotEnterLegacyReconciliation(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "journal-present", true: "unreadable-shape"}[malformed], func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "storage-transactions")
			if malformed {
				if os.WriteFile(path, []byte("not a directory"), 0600) != nil {
					t.Fatal("fixture")
				}
			} else {
				if os.MkdirAll(filepath.Join(path, "reserved-attempt"), 0700) != nil {
					t.Fatal("fixture")
				}
			}
			d := fake.NewSimpleDynamicClient(runtime.NewScheme())
			result, err := NewKubevirtReconciler(d, "ns")(&config.Config{KeyFilePath: filepath.Join(root, "agent.key")}, &http.Client{Transport: noTransactionIO{t}}, nil)
			if err != nil || len(d.Actions()) != 0 || len(result.Events) != 0 {
				t.Fatal("held journal entered legacy effects")
			}
		})
	}
}
