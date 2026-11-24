package server

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func parseRecipient(s string) (*age.X25519Recipient, error) {
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("invalid age recipient: %w", err)
	}
	return r, nil
}

// ageEncrypt encrypts plaintext to r and returns an ASCII-armored age file.
func ageEncrypt(r age.Recipient, plaintext string) (string, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	defer func() {
		_ = aw.Close()
	}()

	w, err := age.Encrypt(aw, r)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = w.Close()
	}()

	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
