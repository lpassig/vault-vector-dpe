// Copyright 2024 The vault-plugin-secrets-vector-dpe Authors
// SPDX-License-Identifier: Apache-2.0

// Package plugin implements a HashiCorp Vault secrets engine for
// Distance-Preserving Encryption (DPE) of vector embeddings.
//
// The plugin uses the Scale-And-Perturb (SAP) scheme to encrypt vectors
// while preserving approximate distance relationships, enabling secure
// similarity search on encrypted data.
package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gonum.org/v1/gonum/mat"
)

const (
	// configStoragePath is the Vault storage path for the encryption configuration.
	configStoragePath = "config/seed"
)

var (
	// errConfigNotInitialized is returned when encryption is attempted before configuration.
	errConfigNotInitialized = errors.New("seed not configured - call config/rotate first")
)

// rotationConfig holds the encryption parameters stored in Vault.
type rotationConfig struct {
	Seed                string  `json:"seed"`
	Dimension           int     `json:"dimension"`
	ScalingFactor       float64 `json:"scaling_factor"`
	ApproximationFactor float64 `json:"approximation_factor"`
}

// vectorBackend is the main backend struct for the DPE secrets engine.
// It caches the orthogonal matrix in memory for performance and uses
// a sync.Pool to reduce GC pressure from temporary allocations.
type vectorBackend struct {
	*framework.Backend

	// matrixLock protects cachedMatrix and cachedConfig.
	// RLock is used for reads, Lock for writes/invalidation.
	matrixLock   sync.RWMutex
	cachedMatrix *mat.Dense
	cachedConfig *rotationConfig

	// floatSlicePool reduces GC pressure by reusing []float64 buffers.
	floatSlicePool sync.Pool
}

// Factory creates a new instance of the vectorBackend.
// This is the entry point called by Vault when the plugin is loaded.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &vectorBackend{
		floatSlicePool: sync.Pool{
			New: func() interface{} {
				// Initialize with 0 length, will be resized as needed.
				s := make([]float64, 0)
				return &s
			},
		},
	}

	b.Backend = &framework.Backend{
		BackendType:    logical.TypeLogical,
		Help:           strings.TrimSpace(backendHelp),
		InitializeFunc: b.initialize,
		Invalidate:     b.invalidate,
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathEncrypt(),
		),
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// initialize is called when the backend is first mounted or Vault starts.
// It can be used for any startup initialization.
func (b *vectorBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	// No special initialization required; matrix is lazily loaded on first request.
	return nil
}

// invalidate is called by Vault when a key in storage is modified.
// This is the "Vault way" to handle cache invalidation rather than ad-hoc checks.
// It ensures the cache is cleared when config changes, on seal, or on plugin reload.
func (b *vectorBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.matrixLock.Lock()
		b.invalidateCacheLocked()
		b.matrixLock.Unlock()
	}
}

// invalidateCacheLocked clears the cached matrix and config.
// MUST be called while holding matrixLock.
func (b *vectorBackend) invalidateCacheLocked() {
	// Memory Hygiene: Zero out the matrix memory before releasing.
	// Gonum Dense matrices wrap a slice; we can zero that slice.
	if b.cachedMatrix != nil {
		data := b.cachedMatrix.RawMatrix().Data
		for i := range data {
			data[i] = 0
		}
	}
	b.cachedMatrix = nil
	b.cachedConfig = nil
}

// readConfig retrieves the encryption configuration from Vault storage.
func (b *vectorBackend) readConfig(ctx context.Context, storage logical.Storage) (*rotationConfig, error) {
	entry, err := storage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cfg rotationConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// writeConfig persists the encryption configuration to Vault storage.
func (b *vectorBackend) writeConfig(ctx context.Context, storage logical.Storage, cfg *rotationConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// getMatrixAndConfig returns the cached orthogonal matrix and config.
// It uses the "Check-Lock-Check" pattern to minimize lock contention.
// The matrix is lazily generated on first access.
func (b *vectorBackend) getMatrixAndConfig(ctx context.Context, storage logical.Storage) (*mat.Dense, *rotationConfig, error) {
	// Fast path: check if already cached (read lock).
	b.matrixLock.RLock()
	if b.cachedMatrix != nil && b.cachedConfig != nil {
		matrix := b.cachedMatrix
		cfg := b.cachedConfig
		b.matrixLock.RUnlock()
		return matrix, cfg, nil
	}
	b.matrixLock.RUnlock()

	// Slow path: acquire write lock and generate matrix.
	b.matrixLock.Lock()
	defer b.matrixLock.Unlock()

	// Double-check after acquiring write lock (another goroutine may have populated it).
	if b.cachedMatrix != nil && b.cachedConfig != nil {
		return b.cachedMatrix, b.cachedConfig, nil
	}

	cfg, err := b.readConfig(ctx, storage)
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		return nil, nil, errConfigNotInitialized
	}

	seedBytes, err := base64.StdEncoding.DecodeString(cfg.Seed)
	if err != nil {
		return nil, nil, fmt.Errorf("decode seed: %w", err)
	}

	// GenerateOrthogonalMatrix internally validates orthogonality and returns
	// an error if the check fails. No need to validate again here.
	matrix, err := GenerateOrthogonalMatrix(seedBytes, cfg.Dimension)
	if err != nil {
		return nil, nil, err
	}

	b.cachedMatrix = matrix
	b.cachedConfig = cfg

	return matrix, cfg, nil
}

// backendHelp is the help text shown when running `vault path-help <mount>`.
const backendHelp = `
The Distance-Preserving Encryption (DPE) secrets engine encrypts vector 
embeddings using the Scale-And-Perturb (SAP) scheme.

This enables secure similarity search on encrypted data in vector databases
like Pinecone, Milvus, or Weaviate.

Key Features:
  • Approximate distance preservation (Cosine Similarity, Euclidean Distance)
  • Probabilistic encryption (same input → different outputs)
  • Resistance to frequency analysis and known-plaintext attacks

Endpoints:
  config/rotate   - Generate a new encryption key and set parameters
  encrypt/vector  - Encrypt a vector embedding

For more information, see the plugin documentation.
`

