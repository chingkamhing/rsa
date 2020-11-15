package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

// root command: no default root command, just print the usage
var rootCmd = &cobra.Command{
	Use:   "",
	Short: "RSA encrypt/decrypt program",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

func init() {
	// add persistent flags
	// FIXME,
}

// Execute is the entry function
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getPrivateKeyFilename(prefix string) string {
	return fmt.Sprintf("%s-private.pem", prefix)
}

func getPublicKeyFilename(prefix string) string {
	return fmt.Sprintf("%s-public.pem", prefix)
}

// Save text string to a file
func saveTextToFile(text, filename string) error {
	textBytes := []byte(text)
	return ioutil.WriteFile(filename, textBytes, 0400)
}

// Read data from file
func readDataFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Decode private key struct from PEM string
func exportPEMStrToPrivKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Decode public key struct from PEM string
func exportPEMStrToPubKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}
