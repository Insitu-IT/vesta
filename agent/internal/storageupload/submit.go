package storageupload

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"vnbui/agent/internal/models"
)

// Submit retries only the identical durable receipt. HTTP 200 is necessary but
// never sufficient: exact durable acceptance identity and assurance are checked.
// No provider operation or upload retry occurs here. The callback returns the
// registered agent credential in memory; neither it nor response error bodies
// are journaled/logged. Caller supplies the existing authenticated TLS client.
func (j *Journal) Submit(ctx context.Context, base string, client *http.Client, agentKey func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Receipt == nil || (j.state.Phase != "prepared" && j.state.Phase != "submitting" && j.state.Phase != "accepted") {
		return nil, ErrHeld
	}
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || client == nil || agentKey == nil {
		return nil, ErrHeld
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if t, ok := transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrHeld
	}
	if j.state.Phase == "accepted" {
		if e = j.save(); e != nil {
			return nil, e
		}
		return copyAcceptance(j.state.Acceptance), nil
	}
	body, _, e := models.CanonicalReceipt(&j.state.Request, *j.state.Receipt)
	if e != nil {
		return nil, ErrHeld
	}
	j.state.Phase = "submitting"
	if e = j.save(); e != nil {
		return nil, e
	}
	response, e := submitReceipt(ctx, base, client, agentKey, j.state.Request.BackupID, body)
	if e != nil {
		return nil, e
	}
	a, e := models.DecodeStorageAcceptance(response, &j.state.Request, *j.state.Receipt)
	if e != nil {
		return nil, ErrHeld
	}
	j.state.Acceptance = a
	j.state.Phase = "accepted"
	if e = j.save(); e != nil {
		return nil, e
	}
	return copyAcceptance(a), nil
}

func submitReceipt(ctx context.Context, base string, client *http.Client, agentKey func(context.Context) (string, error), backup string, body []byte) ([]byte, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || agentKey == nil || len(body) > models.MaxStorageReceiptBytes {
		return nil, ErrHeld
	}
	bounded, e := boundedClient(client)
	if e != nil {
		return nil, e
	}
	key, e := agentKey(ctx)
	if e != nil || key == "" {
		return nil, ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/backups/"+backup+"/prepared-receipt", bytes.NewReader(body))
	if e != nil {
		return nil, ErrHeld
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", key)
	resp, e := bounded.Do(req)
	if e != nil {
		return nil, ErrHeld
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrHeld
	}
	response, e := io.ReadAll(io.LimitReader(resp.Body, models.MaxStorageReceiptBytes+1))
	if e != nil || len(response) > models.MaxStorageReceiptBytes {
		return nil, ErrHeld
	}
	return response, nil
}

func copyAcceptance(a *models.StorageAcceptance) *models.StorageAcceptance {
	copy := *a
	copy.Verification = make([]models.StorageVerification, len(a.Verification))
	for i, v := range a.Verification {
		if v.VersionID != nil {
			value := *v.VersionID
			v.VersionID = &value
		}
		if v.Reason != nil {
			value := *v.Reason
			v.Reason = &value
		}
		copy.Verification[i] = v
	}
	return &copy
}
