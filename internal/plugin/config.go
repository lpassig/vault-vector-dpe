// Copyright 2024 The vault-plugin-secrets-vector-dpe Authors
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// defaultDimension is the default vector dimension (OpenAI text-embedding-3-small).
	defaultDimension = 1536

	// defaultScale is the default scaling factor for the SAP scheme.
	defaultScale = 1.0

	// defaultApproximation is the default noise factor (beta) for the SAP scheme.
	defaultApproximation = 5.0

	// seedLength is the size of the cryptographic seed in bytes (256-bit).
	seedLength = 32

	// memoryWarningThreshold is the memory usage (in bytes) above which we warn.
	// 1536*1536*8 bytes ~ 18MB, 4096*4096*8 bytes ~ 128MB.
	memoryWarningThreshold = 100 * 1024 * 1024
)

// pathConfig returns the path configuration for config/rotate and config/root.
func (b *vectorBackend) pathConfig() []*framework.Path {
	var paths []*framework.Path
	for _, pattern := range []string{"config/rotate", "config/root"} {
		paths = append(paths, &framework.Path{
			Pattern: pattern,
			Fields: map[string]*framework.FieldSchema{
				"dimension": {
					Type:        framework.TypeInt,
					Description: "Dimension of the embedding vectors (e.g., 1536 for OpenAI).",
					Default:     defaultDimension,
				},
				"scaling_factor": {
					Type:        framework.TypeFloat,
					Description: "Scaling factor (s) for the SAP scheme. Must be positive.",
					Default:     defaultScale,
				},
				"approximation_factor": {
					Type:        framework.TypeFloat,
					Description: "Noise factor (β) for the SAP scheme. Higher = more security, less accuracy.",
					Default:     defaultApproximation,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleConfigRotate,
					Summary:  "Generate a new encryption key and set SAP parameters.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleConfigRotate,
					Summary:  "Rotate the encryption key and update SAP parameters.",
				},
			},
			ExistenceCheck:  b.configExists,
			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		})
	}
	return paths
}

// handleConfigRotate generates a new seed and stores the configuration.
func (b *vectorBackend) handleConfigRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dimension, err := parseDimension(data.Get("dimension"))
	if err != nil {
		return nil, err
	}
	if dimension <= 0 {
		return nil, fmt.Errorf("dimension must be positive")
	}
	// Enforce DoS protection limit.
	if dimension > MaxDimension {
		return nil, fmt.Errorf("dimension %d exceeds maximum allowed %d", dimension, MaxDimension)
	}

	// Resource Awareness: Check estimated memory usage.
	estimatedMemory := int64(dimension) * int64(dimension) * 8 // float64 is 8 bytes
	if estimatedMemory > memoryWarningThreshold {
		b.Logger().Warn("configured dimension requires significant memory",
			"dimension", dimension,
			"estimated_bytes", estimatedMemory)
	}

	scalingFactor, err := coerceFloat(data.Get("scaling_factor"))
	if err != nil {
		return nil, fmt.Errorf("invalid scaling_factor: %w", err)
	}
	if scalingFactor <= 0 {
		return nil, fmt.Errorf("scaling_factor must be positive (got %v)", scalingFactor)
	}

	approximationFactor, err := coerceFloat(data.Get("approximation_factor"))
	if err != nil {
		return nil, fmt.Errorf("invalid approximation_factor: %w", err)
	}
	if approximationFactor < 0 {
		return nil, fmt.Errorf("approximation_factor must be non-negative (got %v)", approximationFactor)
	}

	// Generate cryptographically secure seed.
	seed := make([]byte, seedLength)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}

	cfg := &rotationConfig{
		Seed:                base64.StdEncoding.EncodeToString(seed),
		Dimension:           dimension,
		ScalingFactor:       scalingFactor,
		ApproximationFactor: approximationFactor,
	}

	if err := b.writeConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}

	// Invalidate cache - the Invalidate callback will also be triggered by Vault,
	// but we do it explicitly here for immediate effect.
	b.matrixLock.Lock()
	b.invalidateCacheLocked()
	b.matrixLock.Unlock()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"dimension":            dimension,
			"scaling_factor":       scalingFactor,
			"approximation_factor": approximationFactor,
		},
	}
	if estimatedMemory > memoryWarningThreshold {
		resp.AddWarning(fmt.Sprintf(
			"Dimension %d requires approx %d MB of memory for the matrix.",
			dimension, estimatedMemory/1024/1024))
	}
	return resp, nil
}

// configExists checks if configuration already exists (for ExistenceCheck).
func (b *vectorBackend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// parseDimension converts various numeric types to int.
func parseDimension(raw interface{}) (int, error) {
	switch v := raw.(type) {
	case nil:
		return defaultDimension, nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("dimension must be numeric")
	}
}

// Help text constants for the config path.
const pathConfigHelpSyn = `Configure the encryption key and Scale-And-Perturb (SAP) parameters.`

const pathConfigHelpDesc = `
This endpoint generates a new 256-bit cryptographic seed and configures
the Scale-And-Perturb (SAP) encryption parameters.

The seed is used to derive an orthogonal matrix Q via QR decomposition
of a random Gaussian matrix (Haar measure). This matrix is cached in
memory for performance.

Parameters:
  dimension           - Vector dimension (default: 1536, max: 8192)
  scaling_factor      - Scalar multiplier s (default: 1.0, must be > 0)
  approximation_factor - Noise factor β (default: 5.0, must be >= 0)

The encryption formula is: C = s * Q * v + λ

Where λ is a random noise vector sampled uniformly from a ball of
radius (s * β) / 4, providing probabilistic encryption.

WARNING: Calling this endpoint rotates the key. All previously encrypted
vectors will no longer be searchable with the new key.
`

var _ = strings.TrimSpace // Ensure strings import is used

