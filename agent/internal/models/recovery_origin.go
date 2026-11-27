package models

// RestoreOrigin binds the immutable source identities of a signed recovery
// bundle delegated by the enrolled controller. OrgID and AgentID on the
// top-level request still identify the local destination.
type RestoreOrigin struct {
	OrgID   string `json:"org_id"`
	AgentID string `json:"agent_id"`
}

func (origin *RestoreOrigin) Matches(localOrg, localAgent, sourceOrg, sourceAgent string) bool {
	if origin == nil {
		return localOrg == sourceOrg && localAgent == sourceAgent
	}
	return origin.OrgID != "" && origin.AgentID != "" &&
		origin.OrgID == sourceOrg && origin.AgentID == sourceAgent
}

// SigningRegion preserves the effective S3 signing region of historical
// manifests. Existing catalog work still requires an explicit stored region.
func (origin *RestoreOrigin) SigningRegion(region string) string {
	if origin != nil && region == "" {
		return "us-east-1"
	}
	return region
}
