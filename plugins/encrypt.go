package main

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

func (b *vectorBackend) handleEncryptVector(ctx context.Context, req *logical.Request, data *framework.FieldData) (resp *logical.Response, retErr error) {
	// Panic Safety: Recover from panics (e.g. gonum matrix math or memory issues)
	defer func() {
		if r := recover(); r != nil {
			// logical.ErrorResponse returns *logical.Response, which is not an error.
			// But the function signature returns (resp, err).
			// If we want to return a clean error to Vault, we can just set retErr.
			// However, if we want to return a formatted JSON response with the error, we should set resp.
			// Usually, plugins return an error for internal failures.
			retErr = fmt.Errorf("internal plugin error: %v", r)
		}
	}()

	rawVector := data.Get("vector")
	vector, err := parseVector(rawVector)
	if err != nil {
		return nil, err
	}

	// Narrow Locking Scope: getMatrixAndConfig copies pointers under RLock and returns.
	// The heavy matrix multiplication happens later without holding the lock.
	matrix, cfg, err := b.getMatrixAndConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if len(vector) != cfg.Dimension {
		return nil, fmt.Errorf("vector dimension %d does not match configured dimension %d", len(vector), cfg.Dimension)
	}

	// Validate vector elements for NaN/Inf (Input Validation)
	for i, v := range vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
		}
	}

	// Memory Pooling: Get buffer for input backing slice
	inputSlicePtr := b.bufferPool.Get().(*[]float64)
	defer b.bufferPool.Put(inputSlicePtr)

	// Resize buffer if needed
	if cap(*inputSlicePtr) < cfg.Dimension {
		*inputSlicePtr = make([]float64, cfg.Dimension)
	} else {
		*inputSlicePtr = (*inputSlicePtr)[:cfg.Dimension]
	}
	copy(*inputSlicePtr, vector)

	// 1. Apply Orthogonal Rotation: v' = Q * v
	input := mat.NewVecDense(cfg.Dimension, *inputSlicePtr)
	// We need another buffer for the result of rotation.
	// Let's grab another one from the pool.
	rotatedSlicePtr := b.bufferPool.Get().(*[]float64)
	defer b.bufferPool.Put(rotatedSlicePtr)

	if cap(*rotatedSlicePtr) < cfg.Dimension {
		*rotatedSlicePtr = make([]float64, cfg.Dimension)
	} else {
		*rotatedSlicePtr = (*rotatedSlicePtr)[:cfg.Dimension]
	}

	rotatedVec := mat.NewVecDense(cfg.Dimension, *rotatedSlicePtr)
	rotatedVec.MulVec(matrix, input)

	// 2. Generate Noise (Perturbation): lambda_m
	// Use GenerateSecureNoise which implements ChaCha8 CSPRNG
	noise, err := GenerateSecureNoise(cfg.Dimension, cfg.ScalingFactor, cfg.ApproximationFactor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate noise: %w", err)
	}

	// 3. Scale and Add Noise: c = s * v' + lambda_m
	ciphertext := make([]float64, cfg.Dimension)
	rotatedData := rotatedVec.RawVector().Data
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
			// NaN/Inf check
			if math.IsNaN(num) || math.IsInf(num, 0) {
				return nil, fmt.Errorf("vector element %d is invalid (NaN or Inf)", i)
			}
			result[i] = num
		}
		return result, nil
	case []float64:
		// Validate existing float64 slice
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
		// Validate parsed JSON
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
			// NaN/Inf check
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
