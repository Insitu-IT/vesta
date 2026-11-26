//go:build kubevirt

package kubevirt

import (
	"errors"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"vnbui/agent/internal/storageupload"
)

// operationFault contains observations, never credentials, URLs, bodies or
// arbitrary provider error strings. Permanent refusals must not be retried as
// though the original live native backup were harmless idle work.
type operationFault struct {
	Stage                 string `json:"stage"`
	Reason                string `json:"reason"`
	Disposition           string `json:"disposition"`
	HTTPStatus            int    `json:"http_status,omitempty"`
	Volume                int    `json:"volume,omitempty"`
	Page                  int    `json:"page,omitempty"`
	Offset                uint64 `json:"offset,omitempty"`
	RawRanges             int    `json:"raw_ranges,omitempty"`
	StoredRanges          int    `json:"stored_ranges,omitempty"`
	ExpectedNativeVolumes *int   `json:"expected_native_volumes,omitempty"`
	ObservedNativeVolumes *int   `json:"observed_native_volumes,omitempty"`
	ObservedExportLinks   *int   `json:"observed_export_links,omitempty"`
}

func (f *operationFault) Error() string {
	return fmt.Sprintf("%s: %s (%s)", f.Stage, f.Reason, f.Disposition)
}
func (f *operationFault) Unwrap() error { return storageupload.ErrHeld }

func fault(stage, reason, disposition string) *operationFault {
	return &operationFault{Stage: stage, Reason: reason, Disposition: disposition}
}

func faultOf(err error) *operationFault {
	var f *operationFault
	if errors.As(err, &f) {
		copy := *f
		return &copy
	}
	return fault("reconciling", "transaction_observation_unavailable", "transient")
}

func observationFault(resource string, err error) *operationFault {
	f := fault("admission", resource+"_observation_unavailable", "transient")
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		f.HTTPStatus = int(status.Status().Code)
		if f.HTTPStatus >= 400 && f.HTTPStatus < 500 && f.HTTPStatus != 408 && f.HTTPStatus != 429 {
			f.Reason, f.Disposition = resource+"_observation_refused", "refused"
		}
	}
	return f
}
