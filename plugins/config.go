package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultDimension     = 1536
	defaultScale         = 1.0
	defaultApproximation = 5.0
	seedLength           = 32
)

func configPaths(b *vectorBackend) []*framework.Path {
	var paths []*framework.Path
	for _, pattern := range []string{"config/rotate", "config/root"} {
		paths = append(paths, &framework.Path{
			Pattern: pattern,
			Fields: map[string]*framework.FieldSchema{
				"dimension": {
					Type:        framework.TypeInt,
					Description: "Dimension of the embedding vectors.",
					Default:     defaultDimension,
				},
				"scaling_factor": {
					Type:        framework.TypeFloat,
					Description: "Scaling factor for encryption (s in SAP).",
					Default:     defaultScale,
				},
				"approximation_factor": {
					Type:        framework.TypeFloat,
					Description: "Approximation factor for noise generation (beta in SAP).",
					Default:     defaultApproximation,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleConfigRotate,
					Summary:  "Generate or rotate the encryption seed and set parameters.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleConfigRotate,
					Summary:  "Generate or rotate the encryption seed and set parameters.",
				},
			},
			ExistenceCheck:  b.configExists,
			HelpSynopsis:    "Rotate the orthogonal matrix seed and SAP parameters.",
			HelpDescription: "Generates a new seed and configures dimension, scaling factor, and approximation factor.",
		})
	}
	return paths
}

func (b *vectorBackend) handleConfigRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dimension, err := parseDimension(data.Get("dimension"))
	if err != nil {
		return nil, err
	}
	if dimension <= 0 {
		return nil, fmt.Errorf("dimension must be positive")
	}

	scalingFactor, err := coerceFloat(data.Get("scaling_factor"))
	if err != nil {
		return nil, fmt.Errorf("invalid scaling_factor: %w", err)
	}

	approximationFactor, err := coerceFloat(data.Get("approximation_factor"))
	if err != nil {
		return nil, fmt.Errorf("invalid approximation_factor: %w", err)
	}

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

	b.matrixLock.Lock()
	b.invalidateCacheLocked()
	b.matrixLock.Unlock()

	return &logical.Response{
		Data: map[string]interface{}{
			"dimension":            dimension,
			"scaling_factor":       scalingFactor,
			"approximation_factor": approximationFactor,
		},
	}, nil
}

func (b *vectorBackend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

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
