package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// default RSA key bits
const defaultKeyBits = 2048

// default RSA private and public file prefix
const defaultPrefix = "rsa"

// flag variables
var keyBits int
var filenamePrefix string

// key command
var cmdKey = &cobra.Command{
	Use:   "key",
	Short: "RSA generate private and public key pair",
	Args:  cobra.ExactArgs(0),
	Run:   runKey,
}

func init() {
	cmdKey.Flags().IntVar(&keyBits, "bits", defaultKeyBits, "Number of key bits. This also limit the max encrypt text size.")
	cmdKey.Flags().StringVar(&filenamePrefix, "prefix", defaultPrefix, "RSA private and public file prefix")

	rootCmd.AddCommand(cmdKey)
}

func runKey(cmd *cobra.Command, args []string) {
	privateKey, publicKey, err := generateKeyPair(keyBits)
	if err != nil {
		fmt.Println("generate key pair error:", err)
		os.Exit(-1)
	}
	privateFilename := getPrivateKeyFilename(filenamePrefix)
	publicFilename := getPublicKeyFilename(filenamePrefix)
	err = saveTextToFile(exportPrivKeyAsPEMStr(privateKey), privateFilename)
	if err != nil {
		fmt.Printf("save file %q error: %v\n", privateFilename, err)
		os.Exit(-1)
	}
	fmt.Printf("Private file: %v\n", privateFilename)
	err = saveTextToFile(exportPubKeyAsPEMStr(publicKey), publicFilename)
	if err != nil {
		fmt.Printf("save file %q error: %v\n", publicFilename, err)
		os.Exit(-1)
	}
	fmt.Printf("Public file: %v\n", publicFilename)
}

func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// This method requires a random number of bits.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA generate %v bits key error: %w", bits, err)
	}

	// The public key is part of the PrivateKey struct
	return privateKey, &privateKey.PublicKey, nil
}

// Export public key as a string in PEM format
func exportPubKeyAsPEMStr(pubkey *rsa.PublicKey) string {
	pubKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		},
	))
	return pubKeyPem
}

// Export private key as a string in PEM format
func exportPrivKeyAsPEMStr(privkey *rsa.PrivateKey) string {
	privKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		},
	))
	return privKeyPem
}
