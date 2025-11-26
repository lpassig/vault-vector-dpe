package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	mathrand "math/rand/v2"

	"gonum.org/v1/gonum/mat"
)

const MaxDimension = 8192

// GenerateOrthogonalMatrix generates a random orthogonal matrix using QR decomposition.
// This corresponds to the core rotation logic (Q) in the SAP scheme.
func GenerateOrthogonalMatrix(seed []byte, dim int) (*mat.Dense, error) {
	if dim <= 0 {
		return nil, fmt.Errorf("dimension must be positive")
	}
	if dim > MaxDimension {
		return nil, fmt.Errorf("dimension %d exceeds maximum allowed %d", dim, MaxDimension)
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("seed must be exactly 32 bytes (got %d)", len(seed))
	}

	// Warn if dimension is large but within limits
	if dim > 2048 {
		log.Printf("[WARN] vault-dpe: generating %dx%d orthogonal matrix – this can be slow", dim, dim)
	}

	// Use ChaCha8 for high-performance CSPRNG seeded from the key.
	// Copy seed to [32]byte array required by NewChaCha8
	var seed32 [32]byte
	copy(seed32[:], seed)
	rng := mathrand.New(mathrand.NewChaCha8(seed32))

	data := make([]float64, dim*dim)
	for i := range data {
		data[i] = rng.NormFloat64()
	}

	randomMatrix := mat.NewDense(dim, dim, data)

	var qr mat.QR
	qr.Factorize(randomMatrix)

	var q mat.Dense
	qr.QTo(&q)

	// Validate Orthogonality before returning
	if err := ValidateOrthogonality(&q); err != nil {
		return nil, fmt.Errorf("generated matrix failed orthogonality check: %w", err)
	}

	return &q, nil
}

// ValidateOrthogonality checks if Q^T * Q is approximately Identity.
// Tolerance is 1e-6.
func ValidateOrthogonality(q *mat.Dense) error {
	r, c := q.Dims()
	if r != c {
		return fmt.Errorf("matrix is not square: %dx%d", r, c)
	}

	// Compute product = Q^T * Q
	var product mat.Dense
	product.Mul(q.T(), q)

	// Check against Identity
	epsilon := 1e-6
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			val := product.At(i, j)
			expected := 0.0
			if i == j {
				expected = 1.0
			}
			if math.Abs(val-expected) > epsilon {
				return fmt.Errorf("orthogonality check failed at (%d, %d): got %v, expected %v", i, j, val, expected)
			}
		}
	}
	return nil
}

// NewSecureRNG creates a new math/rand/v2.Rand seeded with 32 bytes of
// cryptographic entropy from crypto/rand. It uses the ChaCha8 algorithm.
func NewSecureRNG() (*mathrand.Rand, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return mathrand.New(mathrand.NewChaCha8(seed)), nil
}

// GenerateSecureNoise generates the perturbation vector lambda_m for the SAP scheme
// using a fast, user-space CSPRNG (ChaCha8) seeded with system entropy.
// It fills the provided buffer or allocates a new one if nil.
func GenerateSecureNoise(buffer []float64, dim int, scalingFactor float64, approximationFactor float64) ([]float64, error) {
	// 1. Initialize ChaCha8 CSPRNG
	rng, err := NewSecureRNG()
	if err != nil {
		return nil, err
	}

	// 2. Generate Noise
	return GenerateNormalizedVector(rng, buffer, dim, scalingFactor, approximationFactor)
}

// GenerateNormalizedVector generates the perturbation vector lambda_m for the SAP scheme.
// Logic mirrors IronCore Alloy's crypto.rs:
// 1. u <-- N(0, I_d)
// 2. x' <-- U(0, 1)
// 3. x <-- (s * beta / 4) * (x')^(1/d)
// 4. lambda_m <-- u * x / ||u||
//
// NOTE: This accepts *math/rand/v2.Rand for performance.
// Returns an error if the generated normal vector has zero norm (astronomically unlikely).
func GenerateNormalizedVector(rng *mathrand.Rand, buffer []float64, dim int, scalingFactor float64, approximationFactor float64) ([]float64, error) {
	// Use provided buffer or allocate
	lambdaM := buffer
	if cap(lambdaM) < dim {
		lambdaM = make([]float64, dim)
	} else {
		lambdaM = lambdaM[:dim]
	}

	// 1. Sample u from multivariate normal distribution N(0, I_d)
	// Since covariance is identity, we can just sample d independent standard normals.
	// We use the buffer for 'u' initially to avoid extra allocation,
	// effectively calculating in-place where possible.
	// However, we need to store 'u' while calculating normSq.
	var normSq float64
	for i := 0; i < dim; i++ {
		val := rng.NormFloat64()
		lambdaM[i] = val // Store u in lambdaM temporarily
		normSq += val * val
	}
	uNorm := math.Sqrt(normSq)

	// Guard against division by zero (astronomically unlikely but theoretically possible)
	if uNorm == 0 {
		return nil, fmt.Errorf("generated normal vector has zero norm")
	}

	// 2. Sample x' from uniform distribution U(0, 1)
	xPrime := rng.Float64()

	// 3. Calculate uniform point in ball radius (x)
	// radius R = (s * beta) / 4
	radius := (scalingFactor * approximationFactor) / 4.0
	// x = R * (x')^(1/d)
	x := radius * math.Pow(xPrime, 1.0/float64(dim))

	// 4. Calculate normalized vector lambda_m = u * x / ||u||
	// Reuse lambdaM which holds 'u'
	scale := x / uNorm
	for i := 0; i < dim; i++ {
		lambdaM[i] = lambdaM[i] * scale
	}

	return lambdaM, nil
}
