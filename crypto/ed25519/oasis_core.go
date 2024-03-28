package ed25519

import (
	"crypto/sha512"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/cache"
)

// This file adds the helpers for forcing Tendermint to use oasis-core's
// ad-hoc domain-separation context based signing and verification for
// all Ed25519 signatures.
//
// Engineering wanted to use Ed25519ph/Ed25519ctx, everyone else cried
// about YubiHSM and Ledger's lack of support for said constructs.  So
// instead, we need to force Tendermint to use our ad-hoc thing because
// the whole point of the better constructs is to avoid collisions when
// using the same key to sign with Ed25519pure.
//
// For implementation simplicity, only a single domain-separation context
// is supported.

var (
	oasisDomainSeparator        string
	oasisDomainSeparatorEnabled bool

	// Oasis Protocol uses a very specific definition of Ed25519pure that
	// is slightly different from everyone else.
	verifyOptionsOasis = &ed25519.Options{
		Verify: &ed25519.VerifyOptions{
			AllowSmallOrderA:   false,
			AllowSmallOrderR:   false,
			AllowNonCanonicalA: true,
			AllowNonCanonicalR: true,
		},
	}

	// CachingVerifier stores the decompressed public keys to accelerate
	// repeated signature verification with the same public keys.
	CachingVerifier = cache.NewVerifier(
		cache.NewLRUCache(4096), // Should be big enough?
	)
)

// EnableOasisDomainSeparation enables oasis-core's ad-hoc domain-separated
// signatures scheme for all Ed25519 operations.
//
// This routine should be called in a package level `init()` function,
// before any signing or verification calls are made.
func EnableOasisDomainSeparation(context string) {
	oasisDomainSeparator = context
	oasisDomainSeparatorEnabled = true
}

// OasisDomainSeparationEnabled returns true iff the oasis-core ad hoc
// domain-separated signature scheme is enabled.
func OasisDomainSeparationEnabled() bool {
	return oasisDomainSeparatorEnabled
}

func oasisSignContext(privKey PrivKey, msg []byte) ([]byte, error) {
	prehash := oasisDomainSeparationPrehash(msg)
	return ed25519.Sign(ed25519.PrivateKey(privKey), prehash), nil
}

func oasisVerifyBytesContext(pubKey PubKey, msg, sig []byte) bool {
	prehash := oasisDomainSeparationPrehash(msg)
	return CachingVerifier.VerifyWithOptions(ed25519.PublicKey(pubKey), prehash, sig, verifyOptionsOasis)
}

func OasisVerifyBatchContext(nativePubKeys []ed25519.PublicKey, msgs, sigs [][]byte) ([]bool, error) {
	prehashes := make([][]byte, 0, len(msgs))
	for _, v := range msgs {
		prehashes = append(prehashes, oasisDomainSeparationPrehash(v))
	}
	return VerifyBatch(nativePubKeys, prehashes, sigs)
}

func oasisDomainSeparationPrehash(message []byte) []byte {
	h := sha512.New512_256()
	_, _ = h.Write([]byte(oasisDomainSeparator))
	_, _ = h.Write(message)
	sum := h.Sum(nil)

	return sum[:]
}
