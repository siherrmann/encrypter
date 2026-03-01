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

func TestNewEncrypterClient(t *testing.T) {
	t.Run("creates client with encrypter", func(t *testing.T) {
		client, err := NewEncrypterClient("http://localhost:8080")

		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Encrypter)
		assert.Equal(t, "http://localhost:8080", client.serverURL)
	})
}

func TestEncrypterClientRequestData(t *testing.T) {
	t.Run("returns decrypted payload", func(t *testing.T) {
		plaintext := []byte("encrypted from server")
		ts := httptest.NewServer(EncryptionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(plaintext)
		})))
		defer ts.Close()

		client, err := NewEncrypterClient(ts.URL)
		require.NoError(t, err)

		data, err := client.RequestData("/")

		require.NoError(t, err)
		assert.Equal(t, plaintext, data)
	})

	t.Run("fails for invalid request url", func(t *testing.T) {
		client, err := NewEncrypterClient("://invalid")
		require.NoError(t, err)

		data, err := client.RequestData("/")

		require.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("fails on non success status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer ts.Close()

		client, err := NewEncrypterClient(ts.URL)
		require.NoError(t, err)

		data, err := client.RequestData("/")

		require.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "server returned error status")
	})

	t.Run("fails on invalid json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("this is not json"))
		}))
		defer ts.Close()

		client, err := NewEncrypterClient(ts.URL)
		require.NoError(t, err)

		data, err := client.RequestData("/")

		require.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("fails when encrypted payload is not decryptable", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(model.EncryptedMessage{
				Rx:         "invalid",
				Ry:         "invalid",
				Ciphertext: "invalid",
			})
		}))
		defer ts.Close()

		client, err := NewEncrypterClient(ts.URL)
		require.NoError(t, err)

		data, err := client.RequestData("/")

		require.Error(t, err)
		assert.Nil(t, data)
	})
}
