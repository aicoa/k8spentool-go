package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type requestBindError struct {
	err error
}

func (e *requestBindError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func bindRequestJSON(c *gin.Context, req interface{}) error {
	if err := c.ShouldBindJSON(req); err != nil {
		return &requestBindError{err: err}
	}
	return nil
}

func writeHandlerError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var bindErr *requestBindError
	if errors.As(err, &bindErr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": bindErr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"error": err.Error()})
}
