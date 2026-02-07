package main

import (
	"log"

	"github.com/siherrmann/encrypter"
)

func Client() {
	// Step 1: Client generates ECC key pair (d, Q = d·G)
	client, err := encrypter.NewEncrypterClient("http://localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	// Step 2: Client requests encrypted data from server, providing client's public key handshake
	data, err := client.RequestData("/getData")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("✓ Successfully decrypted data: %s", string(data))
}
