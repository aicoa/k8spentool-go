package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRunProfileRequiresTargetHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewInfoHandler()
	router.POST("/profiles/:id/run", handler.RunProfile)

	req := httptest.NewRequest(http.MethodPost, "/profiles/basic/run", strings.NewReader(`{"timeout_sec":5}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when target_host is missing, got %d", rec.Code)
	}
}
