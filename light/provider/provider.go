package provider

import (
	"context"

	"github.com/cometbft/cometbft/types"
)

// Provider provides information for the light client to sync (verification
// happens in the client).
type Provider interface {
	// ChainID returns the blockchain ID.
	ChainID() string

	// LightBlock returns the LightBlock that corresponds to the given
	// height.
	//
	// 0 - the latest.
	// height must be >= 0.
	//
	// If the provider fails to fetch the LightBlock due to the IO or other
	// issues, an error will be returned.
	// If there's no LightBlock for the given height, ErrLightBlockNotFound
	// error is returned.
	LightBlock(ctx context.Context, height int64) (*types.LightBlock, error)

	// ReportEvidence reports an evidence of misbehavior.
	ReportEvidence(context.Context, types.Evidence) error

	// LightBlockWithPeerID is the same as LightBlock, but the response includes
	// an identifier of the peer that served the block. This is to be used with
	// MalevolentProvider method.
	LightBlockWithPeerID(ctx context.Context, height int64) (*types.LightBlock, string, error)

	// MalevolentProvider notifies the provider that the provider is misbehaving.
	//
	// XXX: This is an Oasis hack to have a callback from the LightClient
	// to the providers in case of malevolent light blocks provided by peers.
	// Because LightClient uses a static-witness set (no support for
	// adding/removing witnesses once the client is initialized) we use
	// "virtual-providers" and in case of a misbehaving peer the provider
	// will internally blacklist the peer and switch to a new one.
	// A more proper/involved solution would be updating the LightClient
	// provider to support dynamic witness set and adding support for subscribing
	// to notifications on failures. But we're trying to keep changes in the
	// fork minimal.
	MalevolentProvider(peerID string)
}
