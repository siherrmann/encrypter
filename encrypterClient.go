package encrypter

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/siherrmann/encrypter/model"
)

type EncrypterClient struct {
	Encrypter *Encrypter
	serverURL string
}

func NewEncrypterClient(serverUrl string) (*EncrypterClient, error) {
	e, err := NewEncrypter()
	if err != nil {
		return nil, err
	}

	return &EncrypterClient{Encrypter: e, serverURL: serverUrl}, nil
}

func (c *EncrypterClient) RequestData(urlPath string) ([]byte, error) {
	// Step 1: Get client's public key handshake
	clientHandshake := c.Encrypter.GetECCHandshake()

	// Step 2: Request encrypted data from server with public key in headers
	req, err := http.NewRequest("POST", c.serverURL+urlPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Encryption-Public-Key-X", clientHandshake.PublicKeyX)
	req.Header.Set("X-Encryption-Public-Key-Y", clientHandshake.PublicKeyY)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned error status: %s", resp.Status)
	}

	// Step 3: Parse encrypted response
	encMsg := &model.EncryptedMessage{}
	err = json.NewDecoder(resp.Body).Decode(encMsg)
	if err != nil {
		return nil, err
	}

	// Step 4: Decrypt data using client's private key (S = d·R)
	data, err := c.Encrypter.DecryptECC(encMsg)
	if err != nil {
		return nil, err
	}

	return data, nil
}
