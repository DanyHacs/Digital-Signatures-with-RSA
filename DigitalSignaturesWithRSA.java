package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/signature"
	"fmt"
	"log"
	"math/big"
)

// GenerateRSAKeyPair generates an RSA key pair (private and public keys)
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// SignMessage signs a message using the RSA private key
func SignMessage(privateKey *rsa.PrivateKey, message string) ([]byte, error) {
	// Hash the message using SHA-256
	hashed := sha256.Sum256([]byte(message))

	// Sign the hashed message using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// VerifySignature verifies the signature of a message using the RSA public key
func VerifySignature(publicKey *rsa.PublicKey, message string, signature []byte) (bool, error) {
	// Hash the message using SHA-256
	hashed := sha256.Sum256([]byte(message))

	// Verify the signature using the public key
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func main() {
	// Generate RSA Key Pair
	privateKey, publicKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}

	// Original message
	message := "This is a secret message!"

	// Sign the message using the private key
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}
	fmt.Printf("Signature: %x\n", signature)

	// Verify the signature using the public key
	isValid, err := VerifySignature(publicKey, message, signature)
	if err != nil {
		log.Fatalf("Error verifying signature: %v", err)
	}

	if isValid {
		fmt.Println("Signature is valid!")
	} else {
		fmt.Println("Signature is invalid!")
	}
}
