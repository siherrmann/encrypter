# encrypter

[![Go Reference](https://pkg.go.dev/badge/github.com/siherrmann/encrypter.svg)](https://pkg.go.dev/github.com/siherrmann/encrypter)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/siherrmann/encrypter/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/siherrmann/encrypter)](http://goreportcard.com/report/siherrmann/encrypter)

ECIES (Elliptic Curve Integrated Encryption Scheme) package with HTTP middleware support written in Go.

## 💡 Goal of this package

This encrypter is meant to provide easy-to-use end-to-end encryption for HTTP APIs. It implements ECIES using ECDH P-256 for key exchange and AES-GCM for authenticated encryption. The package includes both client and server middleware, making it simple to encrypt HTTP responses with minimal setup.

---

## 🛠️ Installation

To integrate the encrypter package into your Go project, use the standard go get command:

```bash
go get github.com/siherrmann/encrypter
```

---

## 🚀 Getting started

### Server-side encryption middleware

Wrap your HTTP handler with the encryption middleware to automatically encrypt responses:

```go
// Create a handler
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Secret data"))
})

// Start server with the wrapped handler
http.Handle("/api/data", encrypter.EncryptionMiddleware(handler))
http.ListenAndServe(":8080", nil)
```

The middleware automatically:

- Reads the client's public key from request headers (`X-Encryption-Public-Key-X` and `X-Encryption-Public-Key-Y`)
- Captures the response from your handler
- Encrypts the response using ECIES
- Returns an encrypted JSON response

### Client-side decryption

Request and decrypt data from an encrypted endpoint:

```go
// Create client
client, err := encrypter.NewEncrypterClient("http://localhost:8080")
if err != nil {
    log.Fatal(err)
}

// Request encrypted data - automatically sends public key and decrypts response
data, err := client.RequestData("/api/data")
if err != nil {
    log.Fatal(err)
}

fmt.Println(string(data)) // "Secret data"
```

You can find complete examples in the [examples/](examples/) folder.

---

## NewEncrypter

`NewEncrypter` creates a new Encrypter instance with generated ECDH P-256 keys. This is the primary constructor for creating encryption contexts.

```go
func NewEncrypter() (*Encrypter, error)
```

The function generates:

- A new ECDH P-256 private key
- The corresponding public key

Returns a pointer to the newly configured `Encrypter` instance, or an error if key generation fails.

---

## Encrypter Methods

### GetECCHandshake

Returns the public key in a format suitable for transmission in HTTP headers or JSON.

```go
func (e *Encrypter) GetECCHandshake() model.Handshake
```

Returns a `Handshake` struct containing the X and Y coordinates of the public key as base64-encoded strings.

### SetPeerPublicKey

Reconstructs a peer's public key from a handshake message.

```go
func (e *Encrypter) SetPeerPublicKey(h model.Handshake) (*ecdh.PublicKey, error)
```

- `h`: A `Handshake` struct containing the peer's public key coordinates

Returns the reconstructed ECDH public key, or an error if the handshake is invalid.

### EncryptECC

Encrypts data using ECIES (Elliptic Curve Integrated Encryption Scheme).

```go
func (e *Encrypter) EncryptECC(recipientPub *ecdh.PublicKey, plaintext []byte) (*model.EncryptedMessage, error)
```

- `recipientPub`: The recipient's ECDH public key
- `plaintext`: The data to encrypt

The encryption process:

1. Generates an ephemeral private key `r`
2. Computes `R = r·G` (ephemeral public key)
3. Computes shared secret `S = r·Q` using ECDH with the recipient's public key
4. Derives an AES-256 key from the shared secret using SHA-256
5. Encrypts the plaintext with AES-GCM

Returns an `EncryptedMessage` containing the ephemeral public key and the ciphertext.

### DecryptECC

Decrypts data that was encrypted using ECIES.

```go
func (e *Encrypter) DecryptECC(encMsg *model.EncryptedMessage) ([]byte, error)
```

- `encMsg`: The encrypted message containing the ephemeral public key and ciphertext

The decryption process:

1. Extracts the ephemeral public key `R` from the message
2. Computes shared secret `S = d·R` using the private key `d`
3. Derives the same AES-256 key from the shared secret using SHA-256
4. Decrypts the ciphertext with AES-GCM

Returns the decrypted plaintext, or an error if decryption fails.

---

## EncryptionMiddleware

`EncryptionMiddleware` wraps an `http.Handler` to automatically encrypt responses using ECIES.

```go
func EncryptionMiddleware(next http.Handler) http.Handler
```

- `next`: The HTTP handler to wrap

The middleware:

- Expects the client's public key in `X-Encryption-Public-Key-X` and `X-Encryption-Public-Key-Y` headers
- Captures the response from the wrapped handler
- Encrypts the response body using ECIES
- Returns the encrypted data as a JSON-encoded `EncryptedMessage`

If the encryption headers are missing or invalid, the middleware returns an appropriate HTTP error.

---

## EncrypterClient

`EncrypterClient` provides a convenient way to make requests to encrypted HTTP endpoints.

### NewEncrypterClient

Creates a new client instance with generated encryption keys.

```go
func NewEncrypterClient(serverUrl string) (*EncrypterClient, error)
```

- `serverURL`: The base URL of the server (e.g., `"http://localhost:8080"`)

Returns a pointer to a new `EncrypterClient` instance, or an error if key generation fails.

### RequestData

Makes a POST request to an encrypted endpoint and automatically handles encryption/decryption.

```go
func (c *EncrypterClient) RequestData(urlPath string) ([]byte, error)
```

- `urlPath`: The path to append to the server URL (e.g., `"/api/data"`)

The method:

1. Sends the client's public key in request headers
2. Receives the encrypted response from the server
3. Decrypts the response using the client's private key

Returns the decrypted response body, or an error if the request or decryption fails.

---

## ⭐ Features

- **ECIES encryption**: Elliptic Curve Integrated Encryption Scheme using ECDH P-256 and AES-GCM
- **HTTP middleware**: Easy-to-use middleware for encrypting HTTP responses
- **Client support**: Built-in client for requesting and decrypting encrypted data
- **Authenticated encryption**: Uses AES-GCM for authenticated encryption with integrity protection
- **Ephemeral keys**: Each encryption uses a new ephemeral key pair for forward secrecy
- **Base64 encoding**: All encrypted data is base64-encoded for easy transmission in JSON
- **Standard library**: Uses Go's standard crypto libraries for proven security
