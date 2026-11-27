package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyBackupWithKeyRequiresAuthenticatedTLS(t *testing.T) {
	handler := NewBackupHandler(nil)
	response := httptest.NewRecorder()
	handler.StartBackup(response, httptest.NewRequest(http.MethodPost, "/api/backups",
		strings.NewReader(`{"backup_id":"fixture","encryption_key":"synthetic-ordinary-data"}`)))
	if response.Code != http.StatusLocked {
		t.Fatalf("expected secure transport refusal before reaching mock executor, got %d", response.Code)
	}
}
