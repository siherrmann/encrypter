package model

import (
	"bytes"
	"net/http"
)

// ResponseRecorder captures the response body and headers
type ResponseRecorder struct {
	header      http.Header
	body        *bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func NewResponseRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		header:     http.Header{},
		body:       &bytes.Buffer{},
		statusCode: http.StatusOK,
	}
}

func (r *ResponseRecorder) Header() http.Header {
	return r.header
}

func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}

func (r *ResponseRecorder) WriteHeader(statusCode int) {
	if !r.wroteHeader {
		r.statusCode = statusCode
		r.wroteHeader = true
	}
}

func (r *ResponseRecorder) BodyBytes() []byte {
	return r.body.Bytes()
}
