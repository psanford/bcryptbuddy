package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/spf13/cobra"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "bcryptbuddy",
		Short: "bcryptbuddy helps you generate and check bcrypt hashes",
	}

	rootCmd.AddCommand(hashCmd())
	rootCmd.AddCommand(verifyCmd())

	rootCmd.Execute()
}

func hashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Hash a password via prompt",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("Password: ")
			pw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Read password error: %s", err)
			}
			fmt.Println()
			pw = bytes.TrimSpace(pw)

			if len(pw) < 1 {
				log.Fatalf("No password provided")
			}

			crypt, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
			if err != nil {
				log.Fatalf("Generate bcrypt hash error: %s", err)
			}
			fmt.Printf("%s\n", crypt)
		},
	}
	return cmd
}

var (
	hashFlag string
)

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a password matches a hash via prompt",
		Run: func(cmd *cobra.Command, args []string) {
			var (
				bcryptHash []byte
				err        error
			)
			if hashFlag == "" {
				fmt.Print("Bcrypt Hash: ")
				reader := bufio.NewReader(os.Stdin)
				bcryptHash, err = reader.ReadBytes('\n')
				if err != nil {
					log.Fatalf("Read bcrypt hash error: %s", err)
				}
				bcryptHash = bytes.TrimSpace(bcryptHash)
			} else {
				bcryptHash = []byte(hashFlag)
			}

			// check the hash is in a valid format before prompting for password
			err = bcrypt.CompareHashAndPassword(bcryptHash, []byte(""))
			if err != nil && err != bcrypt.ErrMismatchedHashAndPassword {
				log.Fatalf("Bad bcrypt hash provided: %s", err)
			}

			fmt.Print("Password: ")
			pw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Read password error: %s", err)
			}
			fmt.Println()
			pw = bytes.TrimSpace(pw)

			if len(pw) < 1 {
				log.Fatalf("No password provided")
			}

			err = bcrypt.CompareHashAndPassword(bcryptHash, pw)
			if err != nil {
				log.Fatalf("Mismatch! %s", err)
			}

			fmt.Println("ok")
		},
	}

	cmd.Flags().StringVarP(&hashFlag, "hash", "", "", "Hash to verify (empty will prompt)")

	return cmd
}
