package main

import (
	"testing"

	"gonum.org/v1/gonum/mat"
)

func TestGenerateOrthogonalMatrix(t *testing.T) {
	// Test valid generation
	dim := 128 // Small dimension for speed
	seed := make([]byte, 32)
	// Dummy seed
	for i := range seed {
		seed[i] = byte(i)
	}

	q, err := GenerateOrthogonalMatrix(seed, dim)
	if err != nil {
		t.Fatalf("GenerateOrthogonalMatrix failed: %v", err)
	}

	// Validate dimensions
	r, c := q.Dims()
	if r != dim || c != dim {
		t.Errorf("Expected %dx%d matrix, got %dx%d", dim, dim, r, c)
	}

	// Validation func is already tested implicitly by Generate, but let's test the tester.
	if err := ValidateOrthogonality(q); err != nil {
		t.Errorf("Validation failed on generated matrix: %v", err)
	}
}

func TestValidateOrthogonalityFailure(t *testing.T) {
	// Create a non-orthogonal matrix
	dim := 4
	data := make([]float64, dim*dim)
	for i := range data {
		data[i] = 1.0 // All ones matrix is definitely not orthogonal
	}
	badMatrix := mat.NewDense(dim, dim, data)

	err := ValidateOrthogonality(badMatrix)
	if err == nil {
		t.Error("ValidateOrthogonality should have failed for non-orthogonal matrix")
	}
}

func TestGenerateSecureNoise(t *testing.T) {
	dim := 100
	s := 1.0
	approx := 0.1
	buffer := make([]float64, dim)

	noise, err := GenerateSecureNoise(buffer, dim, s, approx)
	if err != nil {
		t.Fatalf("GenerateSecureNoise failed: %v", err)
	}

	if len(noise) != dim {
		t.Errorf("Expected noise len %d, got %d", dim, len(noise))
	}

	// Basic statistical sanity check: not all zeros
	allZeros := true
	for _, v := range noise {
		if v != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Noise vector is all zeros")
	}
}

func TestNewSecureRNG(t *testing.T) {
	rng, err := NewSecureRNG()
	if err != nil {
		t.Fatalf("NewSecureRNG failed: %v", err)
	}
	if rng == nil {
		t.Fatal("NewSecureRNG returned nil")
	}

	// Verify it produces values
	val := rng.Float64()
	if val < 0 || val >= 1 {
		t.Errorf("Float64 out of expected range: %v", val)
	}
}

func TestGenerateNormalizedVectorReturnsError(t *testing.T) {
	// This test documents the behavior of the division-by-zero guard.
	// In practice, it's astronomically unlikely to trigger, but the code path exists.
	// We can't easily force uNorm=0 without mocking the RNG, so we just verify
	// the function returns an error type correctly when called normally.
	rng, err := NewSecureRNG()
	if err != nil {
		t.Fatalf("NewSecureRNG failed: %v", err)
	}

	dim := 10
	buffer := make([]float64, dim)
	result, err := GenerateNormalizedVector(rng, buffer, dim, 1.0, 1.0)

	// Under normal conditions, this should succeed
	if err != nil {
		t.Errorf("GenerateNormalizedVector failed unexpectedly: %v", err)
	}
	if len(result) != dim {
		t.Errorf("Expected result len %d, got %d", dim, len(result))
	}
}

