package encrypter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/siherrmann/encrypter/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionMiddleware(t *testing.T) {
	t.Run("rejects missing headers", func(t *testing.T) {
		handler := EncryptionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "encryption headers missing")
	})

	t.Run("rejects invalid public key", func(t *testing.T) {
		handler := EncryptionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Encryption-Public-Key-X", "invalid")
		req.Header.Set("X-Encryption-Public-Key-Y", "invalid")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "invalid public key")
	})

	t.Run("returns encrypted json payload", func(t *testing.T) {
		clientEnc, err := NewEncrypter()
		require.NoError(t, err)

		plaintext := []byte("server secret")
		handler := EncryptionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom", "to-be-cleared")
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write(plaintext)
		}))

		hs := clientEnc.GetECCHandshake()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Encryption-Public-Key-X", hs.PublicKeyX)
		req.Header.Set("X-Encryption-Public-Key-Y", hs.PublicKeyY)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Empty(t, rr.Header().Get("X-Custom"))

		enc := &model.EncryptedMessage{}
		err = json.Unmarshal(rr.Body.Bytes(), enc)
		require.NoError(t, err)
		require.NotEmpty(t, enc.Rx)
		require.NotEmpty(t, enc.Ry)
		require.NotEmpty(t, enc.Ciphertext)

		decrypted, err := clientEnc.DecryptECC(enc)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}
