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

// default RSA private file name
const defaultPrivateKeyFilename = "rsa-private.pem"

// flag variables
var filenamePrivateKey string

// decrypt command
var cmddecrypt = &cobra.Command{
	Use:   "decrypt [cipher text]",
	Short: "RSA decrypt cipher text with a private key",
	Args:  cobra.ExactArgs(1),
	Run:   runDecrypt,
}

func init() {
	cmddecrypt.Flags().StringVar(&filenamePrivateKey, "file", defaultPrivateKeyFilename, "RSA public file name")

	rootCmd.AddCommand(cmddecrypt)
}

func runDecrypt(cmd *cobra.Command, args []string) {
	// get the cipher text
	cipherEncoded := args[0]
	// base64 decode
	cipherText, err := base64.StdEncoding.DecodeString(cipherEncoded)
	if err != nil {
		fmt.Println("base64 decode error:", err)
		os.Exit(-1)
	}
	// get private key
	privateKeyData, err := readDataFromFile(filenamePrivateKey)
	if err != nil {
		fmt.Printf("read file %q error: %v", filenamePrivateKey, err)
		os.Exit(-1)
	}
	privateKey, err := exportPEMStrToPrivKey(privateKeyData)
	if err != nil {
		fmt.Printf("parse pem %q error: %v", filenamePrivateKey, err)
		os.Exit(-1)
	}

	// decrypt string
	plainText, _ := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		cipherText,
		nil,
	)
	if err != nil {
		fmt.Println("decrypt error:", err)
		os.Exit(-1)
	}
	fmt.Println(string(plainText))
}
