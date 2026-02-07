package model

// EncryptedMessage contains the ephemeral public key R and encrypted data
type EncryptedMessage struct {
	Rx         string `json:"rx"`         // Ephemeral public key R.X
	Ry         string `json:"ry"`         // Ephemeral public key R.Y
	Ciphertext string `json:"ciphertext"` // Encrypted message
}
