package main

import (
	"fmt"
	"log"
	"math"
	"math/rand/v2"

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
	rng := rand.New(rand.NewChaCha8(seed32))

	data := make([]float64, dim*dim)
	for i := range data {
		data[i] = rng.NormFloat64()
	}

	randomMatrix := mat.NewDense(dim, dim, data)

	var qr mat.QR
	qr.Factorize(randomMatrix)

	var q mat.Dense
	qr.QTo(&q)

	return &q, nil
}

// GenerateNormalizedVector generates the perturbation vector lambda_m for the SAP scheme.
// Logic mirrors IronCore Alloy's crypto.rs:
// 1. u <-- N(0, I_d)
// 2. x' <-- U(0, 1)
// 3. x <-- (s * beta / 4) * (x')^(1/d)
// 4. lambda_m <-- u * x / ||u||
func GenerateNormalizedVector(rng *rand.Rand, dim int, scalingFactor float64, approximationFactor float64) []float64 {
	// 1. Sample u from multivariate normal distribution N(0, I_d)
	// Since covariance is identity, we can just sample d independent standard normals.
	u := make([]float64, dim)
	var normSq float64
	for i := 0; i < dim; i++ {
		val := rng.NormFloat64()
		u[i] = val
		normSq += val * val
	}
	uNorm := math.Sqrt(normSq)

	// 2. Sample x' from uniform distribution U(0, 1)
	xPrime := rng.Float64()

	// 3. Calculate uniform point in ball radius (x)
	// radius R = (s * beta) / 4
	radius := (scalingFactor * approximationFactor) / 4.0
	// x = R * (x')^(1/d)
	x := radius * math.Pow(xPrime, 1.0/float64(dim))

	// 4. Calculate normalized vector lambda_m = u * x / ||u||
	lambdaM := make([]float64, dim)
	scale := x / uNorm
	for i := 0; i < dim; i++ {
		lambdaM[i] = u[i] * scale
	}

	return lambdaM
}
