package encrypter

import (
	"encoding/base64"
	"testing"

	"github.com/siherrmann/encrypter/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncrypter(t *testing.T) {
	t.Run("creates keys", func(t *testing.T) {
		e, err := NewEncrypter()

		require.NoError(t, err)
		require.NotNil(t, e)
		require.NotNil(t, e.PrivateKey)
		require.NotNil(t, e.PublicKey)
		assert.Nil(t, e.AESKey)
		assert.Nil(t, e.GCM)
	})
}

func TestEncrypterGetECCHandshake(t *testing.T) {
	t.Run("returns public key components", func(t *testing.T) {
		e, err := NewEncrypter()
		require.NoError(t, err)

		hs := e.GetECCHandshake()

		require.NotEmpty(t, hs.PublicKeyX)
		require.NotEmpty(t, hs.PublicKeyY)
		_, err = base64.StdEncoding.DecodeString(hs.PublicKeyX)
		require.NoError(t, err)
		_, err = base64.StdEncoding.DecodeString(hs.PublicKeyY)
		require.NoError(t, err)
	})
}

func TestEncrypterSetPeerPublicKey(t *testing.T) {
	t.Run("accepts valid handshake", func(t *testing.T) {
		sender, err := NewEncrypter()
		require.NoError(t, err)

		receiver, err := NewEncrypter()
		require.NoError(t, err)

		peer, err := receiver.SetPeerPublicKey(sender.GetECCHandshake())

		require.NoError(t, err)
		require.NotNil(t, peer)
		assert.Equal(t, sender.PublicKey.Bytes(), peer.Bytes())
	})

	t.Run("rejects invalid x base64", func(t *testing.T) {
		e, err := NewEncrypter()
		require.NoError(t, err)

		peer, err := e.SetPeerPublicKey(model.Handshake{PublicKeyX: "not-base64", PublicKeyY: "AQ=="})

		require.Error(t, err)
		assert.Nil(t, peer)
	})

	t.Run("rejects invalid y base64", func(t *testing.T) {
		e, err := NewEncrypter()
		require.NoError(t, err)

		peer, err := e.SetPeerPublicKey(model.Handshake{PublicKeyX: "AQ==", PublicKeyY: "not-base64"})

		require.Error(t, err)
		assert.Nil(t, peer)
	})
}

func TestEncrypterEncryptECC(t *testing.T) {
	t.Run("encrypts payload for recipient", func(t *testing.T) {
		sender, err := NewEncrypter()
		require.NoError(t, err)

		receiver, err := NewEncrypter()
		require.NoError(t, err)

		plaintext := []byte("secret payload")
		enc, err := sender.EncryptECC(receiver.PublicKey, plaintext)

		require.NoError(t, err)
		require.NotNil(t, enc)
		assert.NotEmpty(t, enc.Rx)
		assert.NotEmpty(t, enc.Ry)
		assert.NotEmpty(t, enc.Ciphertext)
		assert.NotEqual(t, base64.StdEncoding.EncodeToString(plaintext), enc.Ciphertext)
	})
}

func TestEncrypterDecryptECC(t *testing.T) {
	t.Run("decrypts message encrypted for this key", func(t *testing.T) {
		sender, err := NewEncrypter()
		require.NoError(t, err)

		receiver, err := NewEncrypter()
		require.NoError(t, err)

		plaintext := []byte("very secret")
		enc, err := sender.EncryptECC(receiver.PublicKey, plaintext)
		require.NoError(t, err)

		decrypted, err := receiver.DecryptECC(enc)

		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("fails on invalid rx encoding", func(t *testing.T) {
		e, err := NewEncrypter()
		require.NoError(t, err)

		decrypted, err := e.DecryptECC(&model.EncryptedMessage{Rx: "not-base64", Ry: "AQ==", Ciphertext: "AQ=="})

		require.Error(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("fails on invalid ry encoding", func(t *testing.T) {
		e, err := NewEncrypter()
		require.NoError(t, err)

		decrypted, err := e.DecryptECC(&model.EncryptedMessage{Rx: "AQ==", Ry: "not-base64", Ciphertext: "AQ=="})

		require.Error(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("fails when ciphertext is too short", func(t *testing.T) {
		sender, err := NewEncrypter()
		require.NoError(t, err)

		receiver, err := NewEncrypter()
		require.NoError(t, err)

		hs := sender.GetECCHandshake()
		enc := &model.EncryptedMessage{
			Rx:         hs.PublicKeyX,
			Ry:         hs.PublicKeyY,
			Ciphertext: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
		}

		decrypted, err := receiver.DecryptECC(enc)

		require.Error(t, err)
		assert.Nil(t, decrypted)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})
}
