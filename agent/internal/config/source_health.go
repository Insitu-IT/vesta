package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Installation-owned endpoints are pinned with the accepted operation. They
// must be independent of the source guest's monitoring database and carry no
// credentials. No endpoint is inferred from guest inventory or client input.
type SourceHealthProbe struct {
	Namespace string `json:"namespace"`
	VMName    string `json:"vm_name"`
	URL       string `json:"url"`
}

var healthName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)

func ParseSourceHealthProbes(raw string) ([]SourceHealthProbe, error) {
	if raw == "" {
		return nil, nil
	}
	bad := errors.New("source health probes require unique namespace/VM names and credential-free HTTP(S) endpoints")
	if len(raw) > 64<<10 {
		return nil, bad
	}
	var probes []SourceHealthProbe
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&probes) != nil || d.Decode(new(any)) != io.EOF || probes == nil || len(probes) > 128 {
		return nil, bad
	}
	seen := map[string]bool{}
	for _, p := range probes {
		u, err := url.Parse(p.URL)
		if !healthName.MatchString(p.Namespace) || len(p.Namespace) > 63 || strings.Contains(p.Namespace, ".") || !healthName.MatchString(p.VMName) ||
			err != nil || len(p.URL) > 2048 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") ||
			u.User != nil || strings.ContainsAny(p.URL, "?# \t\r\n") || u.Opaque != "" || seen[p.Namespace+"/"+p.VMName] {
			return nil, bad
		}
		if u.Port() != "" {
			port, err := strconv.Atoi(u.Port())
			if err != nil || port < 1 || port > 65535 {
				return nil, bad
			}
		}
		seen[p.Namespace+"/"+p.VMName] = true
	}
	return probes, nil
}
