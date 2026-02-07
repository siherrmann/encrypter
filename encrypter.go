package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/siherrmann/encrypter/model"
)

// Encrypter holds ECDH and AES-GCM keys
type Encrypter struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
	AESKey     []byte
	GCM        cipher.AEAD
}

// NewEncrypter creates a new Encrypter with ECDH keys
func NewEncrypter() (*Encrypter, error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Encrypter{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

func (e *Encrypter) GetECCHandshake() model.Handshake {
	bytes := e.PublicKey.Bytes()
	// Extract X and Y from uncompressed point (0x04 || X || Y)
	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:65])
	return model.Handshake{
		PublicKeyX: base64.StdEncoding.EncodeToString(x.Bytes()),
		PublicKeyY: base64.StdEncoding.EncodeToString(y.Bytes()),
	}
}

func (e *Encrypter) SetPeerPublicKey(h model.Handshake) (*ecdh.PublicKey, error) {
	bx, err := base64.StdEncoding.DecodeString(h.PublicKeyX)
	if err != nil {
		return nil, err
	}
	by, err := base64.StdEncoding.DecodeString(h.PublicKeyY)
	if err != nil {
		return nil, err
	}

	// Reconstruct uncompressed point: 0x04 || X || Y
	bytes := make([]byte, 1+32+32)
	bytes[0] = 0x04
	copy(bytes[1+32-len(bx):33], bx)
	copy(bytes[33+32-len(by):65], by)

	curve := ecdh.P256()
	return curve.NewPublicKey(bytes)
}

// EncryptECC encrypts data using ECIES
// Steps:
// 1. Generate ephemeral private key r
// 2. Compute R = r·G (ephemeral public key)
// 3. Compute shared secret S = r·Q (recipient's public key)
// 4. Derive AES key from S using SHA-256
// 5. Encrypt plaintext with AES-GCM
func (e *Encrypter) EncryptECC(recipientPub *ecdh.PublicKey, plaintext []byte) (*model.EncryptedMessage, error) {
	// Generate ephemeral ECDH private key r
	curve := ecdh.P256()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// R = r·G (ephemeral public key)
	ephemeralPub := ephemeralPriv.PublicKey()

	// Compute shared secret S = r·Q using ECDH
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}

	// Derive AES key from shared secret using SHA-256
	aesKey := sha256.Sum256(sharedSecret)

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Extract X and Y from ephemeral public key
	pubBytes := ephemeralPub.Bytes()
	Rx := new(big.Int).SetBytes(pubBytes[1:33])
	Ry := new(big.Int).SetBytes(pubBytes[33:65])

	return &model.EncryptedMessage{
		Rx:         base64.StdEncoding.EncodeToString(Rx.Bytes()),
		Ry:         base64.StdEncoding.EncodeToString(Ry.Bytes()),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// DecryptECC decrypts data using ECIES
// Steps:
// 1. Extract ephemeral public key R from message
// 2. Compute shared secret S = d·R (using private key d)
// 3. Derive AES key from S using SHA-256
// 4. Decrypt ciphertext with AES-GCM
func (e *Encrypter) DecryptECC(encMsg *model.EncryptedMessage) ([]byte, error) {
	// Reconstruct ephemeral public key R
	rxBytes, err := base64.StdEncoding.DecodeString(encMsg.Rx)
	if err != nil {
		return nil, err
	}
	ryBytes, err := base64.StdEncoding.DecodeString(encMsg.Ry)
	if err != nil {
		return nil, err
	}

	// Reconstruct uncompressed point: 0x04 || X || Y
	pubBytes := make([]byte, 1+32+32)
	pubBytes[0] = 0x04
	copy(pubBytes[1+32-len(rxBytes):33], rxBytes)
	copy(pubBytes[33+32-len(ryBytes):65], ryBytes)

	curve := ecdh.P256()
	ephemeralPub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}

	// Compute shared secret S = d·R using ECDH
	sharedSecret, err := e.PrivateKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}

	// Derive AES key from shared secret using SHA-256
	aesKey := sha256.Sum256(sharedSecret)

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(encMsg.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertextBytes[:nonceSize]
	ciphertext := ciphertextBytes[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
