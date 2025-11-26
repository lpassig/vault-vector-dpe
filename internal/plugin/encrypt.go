// Copyright 2024 The vault-plugin-secrets-vector-dpe Authors
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gonum.org/v1/gonum/mat"
)

// pathEncrypt returns the path configuration for encrypt/vector.
func (b *vectorBackend) pathEncrypt() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "encrypt/vector",
			Fields: map[string]*framework.FieldSchema{
				"vector": {
					Type:        framework.TypeSlice,
					Description: "Embedding vector to encrypt (array of floats).",
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
			HelpSynopsis:    pathEncryptHelpSyn,
			HelpDescription: pathEncryptHelpDesc,
		},
	}
}

// handleEncryptVector encrypts a vector using the SAP scheme.
// The encryption formula is: C = s * Q * v + λ
// Where Q is the orthogonal matrix, s is the scaling factor, and λ is noise.
func (b *vectorBackend) handleEncryptVector(ctx context.Context, req *logical.Request, data *framework.FieldData) (resp *logical.Response, retErr error) {
	// Panic Safety: Recover from panics (e.g., gonum matrix math or memory issues).
	defer func() {
		if r := recover(); r != nil {
			b.Logger().Error("internal plugin error", "panic", r)
			retErr = fmt.Errorf("internal plugin error")
		}
	}()

	// Parse and validate input vector.
	rawVector := data.Get("vector")
	vector, err := parseVector(rawVector)
	if err != nil {
		return nil, err
	}

	// Get cached matrix and config (narrow lock scope - lock released after pointer copy).
	matrix, cfg, err := b.getMatrixAndConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Dimension check.
	if len(vector) != cfg.Dimension {
		return nil, fmt.Errorf("vector dimension %d does not match configured dimension %d",
			len(vector), cfg.Dimension)
	}

	// Validate vector elements for NaN/Inf (defense in depth).
	for i, v := range vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
		}
	}

	// Validate vector norm (DoS mitigation for numeric overflow).
	var normSq float64
	for _, v := range vector {
		normSq += v * v
	}
	if normSq > 1e12 {
		return nil, fmt.Errorf("vector magnitude too large")
	}

	// Audit Logging: Log request metadata (NOT the vector content).
	b.Logger().Info("vector encryption request",
		"dimension", cfg.Dimension,
		"client_id", req.ClientToken)

	// === Memory Pooling: Get buffers from pool ===

	// Input buffer.
	inputSlicePtr := b.floatSlicePool.Get().(*[]float64)
	defer func() {
		for i := range *inputSlicePtr {
			(*inputSlicePtr)[i] = 0
		}
		b.floatSlicePool.Put(inputSlicePtr)
	}()
	if cap(*inputSlicePtr) < cfg.Dimension {
		*inputSlicePtr = make([]float64, cfg.Dimension)
	} else {
		*inputSlicePtr = (*inputSlicePtr)[:cfg.Dimension]
	}
	copy(*inputSlicePtr, vector)

	// Rotated vector buffer.
	rotatedSlicePtr := b.floatSlicePool.Get().(*[]float64)
	defer func() {
		for i := range *rotatedSlicePtr {
			(*rotatedSlicePtr)[i] = 0
		}
		b.floatSlicePool.Put(rotatedSlicePtr)
	}()
	if cap(*rotatedSlicePtr) < cfg.Dimension {
		*rotatedSlicePtr = make([]float64, cfg.Dimension)
	} else {
		*rotatedSlicePtr = (*rotatedSlicePtr)[:cfg.Dimension]
	}

	// Noise buffer.
	noiseSlicePtr := b.floatSlicePool.Get().(*[]float64)
	defer func() {
		for i := range *noiseSlicePtr {
			(*noiseSlicePtr)[i] = 0
		}
		b.floatSlicePool.Put(noiseSlicePtr)
	}()
	if cap(*noiseSlicePtr) < cfg.Dimension {
		*noiseSlicePtr = make([]float64, cfg.Dimension)
	} else {
		*noiseSlicePtr = (*noiseSlicePtr)[:cfg.Dimension]
	}

	// Ciphertext buffer.
	ciphertextBufPtr := b.floatSlicePool.Get().(*[]float64)
	defer func() {
		for i := range *ciphertextBufPtr {
			(*ciphertextBufPtr)[i] = 0
		}
		b.floatSlicePool.Put(ciphertextBufPtr)
	}()
	if cap(*ciphertextBufPtr) < cfg.Dimension {
		*ciphertextBufPtr = make([]float64, cfg.Dimension)
	} else {
		*ciphertextBufPtr = (*ciphertextBufPtr)[:cfg.Dimension]
	}

	// === Step 1: Apply Orthogonal Rotation: v' = Q * v ===
	input := mat.NewVecDense(cfg.Dimension, *inputSlicePtr)
	rotatedVec := mat.NewVecDense(cfg.Dimension, *rotatedSlicePtr)
	rotatedVec.MulVec(matrix, input)

	// === Step 2: Generate Noise (Perturbation): λ ===
	noise, err := GenerateSecureNoise(*noiseSlicePtr, cfg.Dimension, cfg.ScalingFactor, cfg.ApproximationFactor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate noise: %w", err)
	}

	// === Step 3: Scale and Add Noise: C = s * v' + λ ===
	ciphertextBuf := (*ciphertextBufPtr)[:cfg.Dimension]
	rotatedData := rotatedVec.RawVector().Data
	for i := 0; i < cfg.Dimension; i++ {
		val := cfg.ScalingFactor*rotatedData[i] + noise[i]
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return nil, fmt.Errorf("encryption resulted in invalid value at index %d", i)
		}
		ciphertextBuf[i] = val
	}

	// Copy to result slice (safe to return outside pool lifecycle).
	resultCiphertext := make([]float64, cfg.Dimension)
	copy(resultCiphertext, ciphertextBuf)

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": resultCiphertext,
		},
	}, nil
}

// encryptExists is the ExistenceCheck for the encrypt path.
// This is a stateless endpoint, so we always return true.
func (b *vectorBackend) encryptExists(context.Context, *logical.Request, *framework.FieldData) (bool, error) {
	return true, nil
}

// parseVector converts various input formats to []float64.
// Supports: []float64, []interface{}, JSON string, []string.
func parseVector(raw interface{}) ([]float64, error) {
	if raw == nil {
		return nil, fmt.Errorf("vector is required")
	}

	switch v := raw.(type) {
	case []interface{}:
		// Handle single JSON string wrapped in slice (Vault CLI behavior).
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
			if math.IsNaN(num) || math.IsInf(num, 0) {
				return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
			}
			result[i] = num
		}
		return result, nil

	case []float64:
		for i, num := range v {
			if math.IsNaN(num) || math.IsInf(num, 0) {
				return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
			}
		}
		result := make([]float64, len(v))
		copy(result, v)
		return result, nil

	case string:
		var parsed []float64
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, fmt.Errorf("vector must be JSON array of floats: %w", err)
		}
		for i, num := range parsed {
			if math.IsNaN(num) || math.IsInf(num, 0) {
				return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
			}
		}
		return parsed, nil

	case []string:
		result := make([]float64, len(v))
		for i, val := range v {
			num, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("vector element %d is not a float: %w", i, err)
			}
			if math.IsNaN(num) || math.IsInf(num, 0) {
				return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
			}
			result[i] = num
		}
		return result, nil

	default:
		return nil, fmt.Errorf("vector must be an array of floats")
	}
}

// coerceFloat converts various numeric types to float64.
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

// Help text constants for the encrypt path.
const pathEncryptHelpSyn = `Encrypt a vector embedding using Distance-Preserving Encryption.`

const pathEncryptHelpDesc = `
This endpoint encrypts a vector embedding using the Scale-And-Perturb (SAP)
scheme, preserving approximate distance relationships.

The encryption formula is: C = s * Q * v + λ

Where:
  Q - Orthogonal rotation matrix (derived from secret seed)
  s - Scaling factor
  λ - Random noise vector (fresh for each request)

The encryption is PROBABILISTIC: the same input vector will produce
different ciphertexts on each call. However, the approximate distance
between any two encrypted vectors is preserved.

Input:
  vector - Array of floats (must match configured dimension)

Output:
  ciphertext - Array of floats (encrypted vector)

Example:
  vault write vector/encrypt/vector vector='[0.1, 0.2, 0.3, ...]'
`

