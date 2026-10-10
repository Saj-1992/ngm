// Package apierr defines the standard API error envelope (API_CONTRACT.md).
package apierr

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Error is a client-safe API error. Message must never contain secrets,
// stack traces or internal filesystem paths.
type Error struct {
	Status    int            `json:"-"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id"`
	Retryable bool           `json:"retryable"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New builds an error.
func New(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// WithDetails returns a copy with details attached.
func (e *Error) WithDetails(d map[string]any) *Error {
	c := *e
	c.Details = d
	return &c
}

// Common constructors.
func BadRequest(msg string) *Error { return New(http.StatusBadRequest, "validation_failed", msg) }
func NotFound(what string) *Error  { return New(http.StatusNotFound, "not_found", what+" not found") }
func Conflict(msg string) *Error   { return New(http.StatusConflict, "conflict", msg) }
func Unauthenticated() *Error {
	return New(http.StatusUnauthorized, "unauthenticated", "authentication required")
}
func Forbidden() *Error { return New(http.StatusForbidden, "forbidden", "permission denied") }
func CSRF() *Error      { return New(http.StatusForbidden, "csrf_failed", "cross-site request rejected") }
func PreconditionRequired() *Error {
	return New(http.StatusPreconditionRequired, "precondition_required", "If-Match header required")
}
func PreconditionFailed() *Error {
	return New(http.StatusPreconditionFailed, "precondition_failed", "resource revision changed")
}
func RateLimited() *Error {
	e := New(http.StatusTooManyRequests, "rate_limited", "too many requests")
	e.Retryable = true
	return e
}
func Internal() *Error {
	e := New(http.StatusInternalServerError, "internal", "internal error")
	e.Retryable = true
	return e
}
func Unavailable(msg string) *Error {
	e := New(http.StatusServiceUnavailable, "unavailable", msg)
	e.Retryable = true
	return e
}

// Write renders err as the standard envelope. Non-*Error values become a
// generic internal error so that internal details never leak.
func Write(w http.ResponseWriter, requestID string, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = Internal()
	}
	out := *e
	out.RequestID = requestID
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(out.Status)
	_ = json.NewEncoder(w).Encode(struct {
		Error *Error `json:"error"`
	}{&out})
}
