package storagerestore

import (
	"context"
	"errors"
	"fmt"
	"io"

	"vnbui/agent/internal/models"
)

// WriteVerifiedObject streams one already-admitted object into a private,
// unconsumed destination. Success requires both stored and plaintext digests.
// On error the caller retains/quarantines the partial destination.
func WriteVerifiedObject(ctx context.Context, target models.StorageTarget, object models.StorageObjectReceipt, encrypted bool, key []byte, open ObjectOpener, destination io.Writer) (err error) {
	if object.PlaintextBytes < 0 || object.CiphertextBytes < 0 || object.PlaintextBytes > 1<<60 || object.CiphertextBytes > 1<<60 {
		return errors.New("invalid restore object bounds")
	}
	ciphertext, close, err := openObject(ctx, target, object, open)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, close()) }()
	var source io.Reader = ciphertext
	if encrypted {
		source, err = decryptReader(ciphertext, key)
		if err != nil {
			return err
		}
	}
	plaintext := measure(source, object.PlaintextBytes)
	if _, err = io.CopyBuffer(destination, plaintext, make([]byte, copyBufferBytes)); err != nil {
		return err
	}
	if err = plaintext.verify(object.PlaintextBytes, object.PlaintextSHA256); err != nil {
		return fmt.Errorf("plaintext: %w", err)
	}
	if err = ciphertext.verify(object.CiphertextBytes, object.CiphertextSHA256); err != nil {
		return fmt.Errorf("ciphertext: %w", err)
	}
	return ctx.Err()
}
