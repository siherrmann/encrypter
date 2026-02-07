package encrypter

import (
	"encoding/json"
	"net/http"

	"github.com/siherrmann/encrypter/model"
)

// EncryptionMiddleware wraps an http.Handler to encrypt responses
// Client must send their public key in X-Encryption-Public-Key-X and X-Encryption-Public-Key-Y headers
// Response will be encrypted using ECIES and returned as EncryptedMessage JSON
func EncryptionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if encryption is requested
		pubKeyX := r.Header.Get("X-Encryption-Public-Key-X")
		pubKeyY := r.Header.Get("X-Encryption-Public-Key-Y")

		if pubKeyX == "" || pubKeyY == "" {
			http.Error(w, "encryption headers missing", http.StatusBadRequest)
			return
		}

		// Parse client's public key
		encrypter, err := NewEncrypter()
		if err != nil {
			http.Error(w, "encryption setup failed", http.StatusInternalServerError)
			return
		}

		handshake := model.Handshake{
			PublicKeyX: pubKeyX,
			PublicKeyY: pubKeyY,
		}
		recipientPub, err := encrypter.SetPeerPublicKey(handshake)
		if err != nil {
			http.Error(w, "invalid public key", http.StatusBadRequest)
			return
		}

		// Call the next handler and capture the response
		recorder := model.NewResponseRecorder()
		next.ServeHTTP(recorder, r)

		// Encrypt the response body
		encMsg, err := encrypter.EncryptECC(recipientPub, recorder.BodyBytes())
		if err != nil {
			http.Error(w, "encryption failed", http.StatusInternalServerError)
			return
		}

		// Clear any headers that were set and write only encrypted response
		for k := range w.Header() {
			w.Header().Del(k)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(encMsg)
	})
}
