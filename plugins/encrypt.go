package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	mathrand "math/rand/v2"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gonum.org/v1/gonum/mat"
)

func encryptPaths(b *vectorBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "encrypt/vector",
			Fields: map[string]*framework.FieldSchema{
				"vector": {
					Type:        framework.TypeSlice,
					Description: "Embedding vector to encrypt.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleEncryptVector,
					Summary:  "Encrypt a vector using the Scale-And-Perturb scheme.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleEncryptVector,
					Summary:  "Encrypt a vector using the Scale-And-Perturb scheme.",
				},
			},
			ExistenceCheck:  b.encryptExists,
			HelpSynopsis:    "Encrypt vectors using approximate distance-preserving encryption.",
			HelpDescription: "Applies the Scale-And-Perturb scheme: c = s*Q*v + noise, where Q is orthogonal.",
		},
	}
}

func (b *vectorBackend) handleEncryptVector(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawVector := data.Get("vector")
	vector, err := parseVector(rawVector)
	if err != nil {
		return nil, err
	}

	matrix, cfg, err := b.getMatrixAndConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if len(vector) != cfg.Dimension {
		return nil, fmt.Errorf("vector dimension %d does not match configured dimension %d", len(vector), cfg.Dimension)
	}

	// Validate vector elements for NaN/Inf
	for i, v := range vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
		}
	}

	// SAP Encryption Logic:
	// 1. Apply Orthogonal Rotation: v' = Q * v
	input := mat.NewVecDense(cfg.Dimension, append([]float64(nil), vector...))
	var rotated mat.VecDense
	output := &rotated
	output.MulVec(matrix, input)

	// 2. Generate Noise (Perturbation): lambda_m
	// Fix: Use crypto/rand -> ChaCha8 for high performance CSPRNG per request.
	// We generate a 32-byte seed from crypto/rand for every request.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Use ChaCha8 (math/rand/v2) for fast CSPRNG
	rng := mathrand.New(mathrand.NewChaCha8(seed))

	// Note: GenerateNormalizedVector now accepts *math/rand/v2.Rand
	// We need to update GenerateNormalizedVector signature in matrix_utils.go first?
	// Wait, I already updated matrix_utils.go to use math/rand/v2 but let's check the signature I wrote.
	// I wrote `func GenerateNormalizedVector(rng *rand.Rand, ...)` where rand is `math/rand/v2`.
	// So this should match.
	noise := GenerateNormalizedVector(rng, cfg.Dimension, cfg.ScalingFactor, cfg.ApproximationFactor)

	// 3. Scale and Add Noise: c = s * v' + lambda_m
	ciphertext := make([]float64, cfg.Dimension)
	rotatedData := output.RawVector().Data
	for i := 0; i < cfg.Dimension; i++ {
		val := cfg.ScalingFactor*rotatedData[i] + noise[i]
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return nil, fmt.Errorf("encryption resulted in invalid value at index %d", i)
		}
		ciphertext[i] = val
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
		},
	}, nil
}

func parseVector(raw interface{}) ([]float64, error) {
	if raw == nil {
		return nil, fmt.Errorf("vector is required")
	}

	switch v := raw.(type) {
	case []interface{}:
		if len(v) == 1 {
			if str, ok := v[0].(string); ok {
				return parseVector(str)
			}
		}
		result := make([]float64, len(v))
		for i, val := range v {
			num, err := coerceFloat(val)
			if err != nil {
				return nil, fmt.Errorf("vector element %d is not a float: %w", i, err)
			}
			result[i] = num
		}
		return result, nil
	case []float64:
		result := make([]float64, len(v))
		copy(result, v)
		return result, nil
	case string:
		var parsed []float64
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, fmt.Errorf("vector must be JSON array of floats: %w", err)
		}
		return parsed, nil
	case []string:
		result := make([]float64, len(v))
		for i, val := range v {
			num, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("vector element %d is not a float: %w", i, err)
			}
			result[i] = num
		}
		return result, nil
	default:
		return nil, fmt.Errorf("vector must be an array of floats")
	}
}

func (b *vectorBackend) encryptExists(context.Context, *logical.Request, *framework.FieldData) (bool, error) {
	// Stateless endpoint; always allow the operation.
	return true, nil
}

func coerceFloat(val interface{}) (float64, error) {
	switch t := val.(type) {
	case float64:
		return t, nil
	case float32:
		return float64(t), nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case json.Number:
		return t.Float64()
	case string:
		return strconv.ParseFloat(t, 64)
	default:
		return 0, fmt.Errorf("unsupported type %T", val)
	}
}
