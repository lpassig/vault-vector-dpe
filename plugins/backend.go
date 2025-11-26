package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gonum.org/v1/gonum/mat"
)

const configStoragePath = "config/seed"

var errConfigNotInitialized = errors.New("seed not configured - call config/rotate first")

type rotationConfig struct {
	Seed                string  `json:"seed"`
	Dimension           int     `json:"dimension"`
	ScalingFactor       float64 `json:"scaling_factor"`
	ApproximationFactor float64 `json:"approximation_factor"`
}

type vectorBackend struct {
	*framework.Backend

	matrixLock     sync.RWMutex
	cachedMatrix   *mat.Dense
	cachedConfig   *rotationConfig
	floatSlicePool sync.Pool
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &vectorBackend{
		floatSlicePool: sync.Pool{
			New: func() interface{} {
				// Initialize with 0 length, will be resized as needed
				s := make([]float64, 0)
				return &s
			},
		},
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp(),
		Paths: framework.PathAppend(
			configPaths(b),
			encryptPaths(b),
		),
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

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

func (b *vectorBackend) writeConfig(ctx context.Context, storage logical.Storage, cfg *rotationConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (b *vectorBackend) invalidateCacheLocked() {
	// Memory Hygiene: Attempt to zero out the matrix memory if possible.
	// Gonum Dense matrices wrap a slice. We can zero that slice.
	if b.cachedMatrix != nil {
		data := b.cachedMatrix.RawMatrix().Data
		for i := range data {
			data[i] = 0
		}
	}
	b.cachedMatrix = nil
	b.cachedConfig = nil
}

func (b *vectorBackend) getMatrixAndConfig(ctx context.Context, storage logical.Storage) (*mat.Dense, *rotationConfig, error) {
	b.matrixLock.RLock()
	if b.cachedMatrix != nil && b.cachedConfig != nil {
		matrix := b.cachedMatrix
		cfg := b.cachedConfig
		b.matrixLock.RUnlock()
		return matrix, cfg, nil
	}
	b.matrixLock.RUnlock()

	b.matrixLock.Lock()
	defer b.matrixLock.Unlock()

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

func backendHelp() string {
	return `
The Distance-Preserving Encryption secrets engine rotates embedding vectors
using an orthogonal matrix derived from a stored seed. It implements the Scale-And-Perturb
scheme to provide approximate distance preservation with enhanced security against
frequency-finding and known-plaintext attacks.`
}
