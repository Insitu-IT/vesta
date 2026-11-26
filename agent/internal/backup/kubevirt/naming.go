//go:build kubevirt

package kubevirt

import (
	"strings"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/storageupload"
)

func pullBackupName(t *pullTransaction) string {
	prefix, _ := config.NormalizeKubevirtResourcePrefix(t.ResourcePrefix)
	return prefix + "-" + strings.ToLower(t.BackupID)
}
func (e *Executor) trackerName(identity string) string {
	return trackerName(e.cfg.KubevirtPrefix(), identity)
}

func (e *Executor) namingMatches(s *storageupload.State) bool {
	prefix, err := config.NormalizeKubevirtResourcePrefix(s.ResourcePrefix)
	if err != nil || prefix != e.cfg.KubevirtPrefix() {
		return false
	}
	if n := s.Native; n != nil {
		expected := []string{trackerName(prefix, s.Request.Plan.Source.Namespace+"/"+s.Request.Plan.Source.VMUID), prefix + "-" + s.Request.BackupID, prefix + "-" + s.Request.BackupID + "-token"}
		if len(n.Objects) != len(expected) {
			return false
		}
		for i, name := range expected {
			if n.Objects[i].Name != name {
				return false
			}
		}
	}
	return true
}
func (e *Executor) pullNamingMatches(t *pullTransaction) bool {
	prefix, err := config.NormalizeKubevirtResourcePrefix(t.ResourcePrefix)
	if err != nil || prefix != e.cfg.KubevirtPrefix() {
		return false
	}
	// Old journals retain the exact tracker/UID they recorded. Never let a
	// recognized other-profile tracker become cleanup authority via a missing prefix.
	for _, other := range []string{"vnbui", "vesta"} {
		if other != prefix && strings.HasPrefix(t.Tracker, other+"-") {
			return false
		}
	}
	return true
}
