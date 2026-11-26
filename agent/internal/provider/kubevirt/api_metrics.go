//go:build kubevirt

package kubevirt

import (
	"net/http"
	"strconv"
	"strings"
)

// Only fixed labels leave this function. URL names, namespaces, groups, query
// strings and transport errors must never become metric labels.
func apiMetricLabels(r *http.Request, response *http.Response, err error) (string, string, string) {
	method := r.Method
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		method = "OTHER"
	}
	resource := "other"
	path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var rest []string
	if len(path) >= 2 && path[0] == "api" {
		rest = path[2:]
	} else if len(path) >= 3 && path[0] == "apis" {
		rest = path[3:]
	}
	if len(rest) >= 3 && rest[0] == "namespaces" {
		rest = rest[2:]
	}
	if len(rest) > 0 {
		switch rest[0] {
		case "virtualmachines", "virtualmachineinstances", "virtualmachinebackups", "virtualmachinebackuptrackers", "virtualmachineexports", "persistentvolumeclaims", "persistentvolumes", "services", "pods", "endpointslices", "secrets", "namespaces", "storageclasses", "configmaps", "kubevirts", "hyperconvergeds", "customresourcedefinitions":
			resource = rest[0]
		}
	}
	status := "other"
	if err != nil || response == nil {
		status = "transport_error"
	} else {
		switch response.StatusCode {
		case 200, 201, 202, 204, 400, 401, 403, 404, 409, 410, 422, 429, 500, 502, 503, 504:
			status = strconv.Itoa(response.StatusCode)
		}
	}
	return method, resource, status
}
