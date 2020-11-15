package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// default RSA public file name
const defaultPublicKeyFilename = "rsa-public.pem"

// flag variables
var filenamePublicKey string

// encrypt command
var cmdEncrypt = &cobra.Command{
	Use:   "encrypt [input text]",
	Short: "RSA encrypt input text with a public key",
	Args:  cobra.ExactArgs(1),
	Run:   runEncrypt,
}

func init() {
	cmdEncrypt.Flags().StringVar(&filenamePublicKey, "file", defaultPublicKeyFilename, "RSA public file name")

	rootCmd.AddCommand(cmdEncrypt)
}

func runEncrypt(cmd *cobra.Command, args []string) {
	// get the input text
	plaintext := []byte(args[0])
	// get public key
	publicKeyData, err := readDataFromFile(filenamePublicKey)
	if err != nil {
		fmt.Printf("read file %q error: %v", filenamePublicKey, err)
		os.Exit(-1)
	}
	publicKey, err := exportPEMStrToPubKey(publicKeyData)
	if err != nil {
		fmt.Printf("parse pem %q error: %v", filenamePublicKey, err)
		os.Exit(-1)
	}
	maxSize := getMaxEncryptMaxSize(publicKey.Size())
	if len(plaintext) > maxSize {
		fmt.Printf("input text size must be less than %d size\n", maxSize)
		os.Exit(-1)
	}

	// encrypt string
	cipherText, _ := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		nil,
	)
	if err != nil {
		fmt.Println("encrypt error:", err)
		os.Exit(-1)
	}
	encoded := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println(encoded)
}

// max encrypt text max size: key size - 2 32-byte hash - 2 byte
func getMaxEncryptMaxSize(size int) int {
	return size - 2*32 - 2
}
