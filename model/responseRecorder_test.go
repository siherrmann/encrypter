package model

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResponseRecorder(t *testing.T) {
	t.Run("initializes defaults", func(t *testing.T) {
		r := NewResponseRecorder()

		require.NotNil(t, r)
		require.NotNil(t, r.header)
		require.NotNil(t, r.body)
		assert.Equal(t, http.StatusOK, r.statusCode)
		assert.False(t, r.wroteHeader)
		assert.Empty(t, r.BodyBytes())
	})
}

func TestResponseRecorderHeader(t *testing.T) {
	t.Run("returns mutable header map", func(t *testing.T) {
		r := NewResponseRecorder()

		h := r.Header()
		h.Set("X-Test", "value")

		assert.Equal(t, "value", r.Header().Get("X-Test"))
	})
}

func TestResponseRecorderWrite(t *testing.T) {
	t.Run("writes body and sets implicit status", func(t *testing.T) {
		r := NewResponseRecorder()

		n, err := r.Write([]byte("hello"))

		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("hello"), r.BodyBytes())
		assert.Equal(t, http.StatusOK, r.statusCode)
		assert.True(t, r.wroteHeader)
	})

	t.Run("appends on multiple writes", func(t *testing.T) {
		r := NewResponseRecorder()

		_, err := r.Write([]byte("he"))
		require.NoError(t, err)
		_, err = r.Write([]byte("llo"))
		require.NoError(t, err)

		assert.Equal(t, []byte("hello"), r.BodyBytes())
	})
}

func TestResponseRecorderWriteHeader(t *testing.T) {
	t.Run("sets status once", func(t *testing.T) {
		r := NewResponseRecorder()

		r.WriteHeader(http.StatusCreated)
		r.WriteHeader(http.StatusBadRequest)

		assert.Equal(t, http.StatusCreated, r.statusCode)
		assert.True(t, r.wroteHeader)
	})
}

func TestResponseRecorderBodyBytes(t *testing.T) {
	t.Run("returns current body bytes", func(t *testing.T) {
		r := NewResponseRecorder()
		_, err := r.Write([]byte("payload"))
		require.NoError(t, err)

		body := r.BodyBytes()

		assert.Equal(t, []byte("payload"), body)
	})
}
