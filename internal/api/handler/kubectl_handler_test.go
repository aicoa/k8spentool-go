package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestKubectlDeleteRequiresYAMLOrResourceName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewKubectlHandler()
	router.POST("/kubectl/delete", handler.Delete)

	req := httptest.NewRequest(http.MethodPost, "/kubectl/delete", strings.NewReader(`{"target_host":"demo.local"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when delete mode is missing, got %d", rec.Code)
	}
}
