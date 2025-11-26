// Copyright 2024 The vault-plugin-secrets-vector-dpe Authors
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"math"
	"testing"
)

func TestParseVector(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid float slice",
			input:   []float64{1.0, 2.0, 3.0},
			wantLen: 3,
			wantErr: false,
		},
		{
			name:    "valid int slice",
			input:   []interface{}{1, 2, 3},
			wantLen: 3,
			wantErr: false,
		},
		{
			name:    "NaN value",
			input:   []float64{1.0, math.NaN()},
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "Inf value",
			input:   []float64{1.0, math.Inf(1)},
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "JSON string",
			input:   "[1.1, 2.2]",
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "String array",
			input:   []string{"1.1", "2.2"},
			wantLen: 2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVector(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("parseVector() len = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}

