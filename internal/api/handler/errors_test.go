package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWriteHandlerErrorUsesBadRequestForBindErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/bind", func(c *gin.Context) {
		var req struct {
			Name string `json:"name" binding:"required"`
		}
		if err := bindRequestJSON(c, &req); err != nil {
			writeHandlerError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"name": req.Name})
	})

	req := httptest.NewRequest(http.MethodPost, "/bind", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bind error, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteHandlerErrorUsesStatusOKForOperationalErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/runtime", func(c *gin.Context) {
		writeHandlerError(c, errRuntime("boom"))
	})

	req := httptest.NewRequest(http.MethodGet, "/runtime", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for runtime error envelope, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected json response, got %v", err)
	}
	if body["error"] != "boom" {
		t.Fatalf("expected runtime error payload, got %#v", body)
	}
}

type errRuntime string

func (e errRuntime) Error() string { return string(e) }
