package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var cryptCmd = &cobra.Command{
	Use:               "crypt",
	Short:             "Make password hash for the authfile backend",
	Long:              "Make password hash for the authfile backend. The password is read from the terminal, or from the first line of standard input if it is not a terminal.",
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, _ []string) error {
		password, err := readPassword(cmd.ErrOrStderr(), "Password to be hashed: ")
		if err != nil {
			return err
		}
		hash, err := hashPassword(password)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", hash)
		return err
	},
}

func readPassword(prompt io.Writer, msg string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		_, _ = fmt.Fprint(prompt, msg)
		defer func() { _, _ = fmt.Fprintln(prompt) }()
		return term.ReadPassword(fd)
	}
	return readLine(os.Stdin)
}

func readLine(r io.Reader) ([]byte, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func hashPassword(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("cannot hash password: %w", err)
	}
	return hash, nil
}

func init() {
	RootCmd.AddCommand(cryptCmd)
}
