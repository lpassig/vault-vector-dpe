# Vault Plugin: Secrets Vector DPE

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Vault](https://img.shields.io/badge/Vault-1.15+-000000?style=flat&logo=vault)](https://www.vaultproject.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A **HashiCorp Vault Secrets Engine** that implements **Approximate Distance-Preserving Encryption (DPE)** for vector embeddings using the **Scale-And-Perturb (SAP)** scheme.

This plugin enables **secure vector search** on encrypted data in vector databases like Pinecone, Milvus, or Weaviate—without exposing the raw embeddings.

---

## 🔑 Key Features

| Feature | Description |
|---------|-------------|
| **Distance Preservation** | Encrypted vectors maintain approximate Cosine Similarity and Euclidean Distance |
| **Probabilistic Encryption** | Same input → different outputs (CPA resistance) |
| **Tunable Security** | Configure the accuracy/security trade-off via `approximation_factor` |
| **High Performance** | ChaCha8 CSPRNG, matrix caching, memory pooling |
| **Production Ready** | Input validation, DoS protection, panic recovery, audit logging |

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VAULT PLUGIN ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐                                                               │
│  │  CLIENT  │                                                               │
│  │ (App/ML) │                                                               │
│  └────┬─────┘                                                               │
│       │                                                                     │
│       │ POST /vector/encrypt/vector                                         │
│       │ { "vector": [0.1, 0.2, ...] }                                       │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         VAULT SERVER                                 │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │                    vault-plugin-secrets-vector-dpe           │    │   │
│  │  │                                                              │    │   │
│  │  │   ┌──────────────┐    ┌──────────────────────────────────┐  │    │   │
│  │  │   │   CONFIG     │    │         RUNTIME (Cached)         │  │    │   │
│  │  │   │              │    │                                  │  │    │   │
│  │  │   │  • Seed (32B)│───▶│  • Orthogonal Matrix Q (N×N)    │  │    │   │
│  │  │   │  • Dimension │    │  • Derived via QR Decomposition  │  │    │   │
│  │  │   │  • Scale (s) │    │  • Haar-distributed rotation     │  │    │   │
│  │  │   │  • Beta (β)  │    │                                  │  │    │   │
│  │  │   └──────────────┘    └──────────────────────────────────┘  │    │   │
│  │  │                                                              │    │   │
│  │  │   ┌──────────────────────────────────────────────────────┐  │    │   │
│  │  │   │              ENCRYPTION (Per Request)                 │  │    │   │
│  │  │   │                                                       │  │    │   │
│  │  │   │   Input: v (plaintext vector)                        │  │    │   │
│  │  │   │                                                       │  │    │   │
│  │  │   │   1. Rotate:    v' = Q × v                           │  │    │   │
│  │  │   │   2. Generate:  λ  ← ChaCha8(crypto/rand)            │  │    │   │
│  │  │   │   3. Encrypt:   C  = s·v' + λ                        │  │    │   │
│  │  │   │                                                       │  │    │   │
│  │  │   │   Output: C (ciphertext vector)                      │  │    │   │
│  │  │   └──────────────────────────────────────────────────────┘  │    │   │
│  │  │                                                              │    │   │
│  │  └──────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       │ Response: { "ciphertext": [1.24, -0.55, ...] }                     │
│       ▼                                                                     │
│  ┌──────────┐                                                               │
│  │  CLIENT  │───────────────▶ Vector Database (Pinecone, Milvus, etc.)     │
│  └──────────┘                                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Math: Scale-And-Perturb (SAP)

$$C = s \cdot Q \cdot v + \lambda$$

| Symbol | Description |
|--------|-------------|
| $Q$ | Orthogonal matrix derived from secret seed (Haar measure) |
| $s$ | Scaling factor (amplifies signal) |
| $\lambda$ | Random noise vector (fresh per request, from ball of radius $s\beta/4$) |
| $\beta$ | Approximation factor (controls noise magnitude) |

The noise $\lambda$ makes encryption **probabilistic**: encrypting the same vector twice yields different ciphertexts, preventing frequency analysis.

---

## 🚀 Installation

### Prerequisites

- Go 1.22+
- HashiCorp Vault 1.15+

### Build

```bash
# Clone the repository
git clone https://github.com/lpassig/vault-plugin-secrets-vector-dpe.git
cd vault-plugin-secrets-vector-dpe

# Build the plugin
make build

# Output:
#   bin/vault-plugin-secrets-vector-dpe
#   bin/vault-plugin-secrets-vector-dpe.sha256
```

### Register with Vault

```bash
# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='your-token'

# Get the SHA256 checksum
SHA256=$(cat bin/vault-plugin-secrets-vector-dpe.sha256)

# Register the plugin
vault plugin register \
    -sha256=$SHA256 \
    -command=vault-plugin-secrets-vector-dpe \
    secret vault-plugin-secrets-vector-dpe

# Enable the secrets engine
vault secrets enable -path=vector vault-plugin-secrets-vector-dpe
```

---

## ⚙️ Configuration

Initialize the encryption key and parameters:

```bash
vault write vector/config/rotate \
    dimension=1536 \
    scaling_factor=10.0 \
    approximation_factor=5.0
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dimension` | int | 1536 | Vector dimension (max: 8192) |
| `scaling_factor` | float | 1.0 | Scalar multiplier $s$ (must be > 0) |
| `approximation_factor` | float | 5.0 | Noise factor $\beta$ (higher = more secure, less accurate) |

> ⚠️ **Warning:** Calling `config/rotate` generates a new key. Previously encrypted vectors will no longer be searchable.

---

## 🔒 Usage

### Encrypt a Vector

```bash
vault write -format=json vector/encrypt/vector \
    vector='[0.1, 0.5, -0.2, 0.8, ...]'
```

### Response

```json
{
  "data": {
    "ciphertext": [1.245, -0.552, 0.003, 2.891, ...]
  }
}
```

### Probabilistic Check

Encrypting the same vector twice produces **different** ciphertexts:

```bash
# First encryption
C1=$(vault write -format=json vector/encrypt/vector vector='[0.1, 0.2]' | jq '.data.ciphertext')

# Second encryption (same input)
C2=$(vault write -format=json vector/encrypt/vector vector='[0.1, 0.2]' | jq '.data.ciphertext')

# C1 ≠ C2 (probabilistic encryption)
```

---

## 🛡️ Production Hardening

### 1. Access Control

```bash
# Create a policy for the ingestion service only
vault policy write vector-encrypt - <<EOF
path "vector/encrypt/vector" {
  capabilities = ["create", "update"]
}
EOF

# Use AppRole authentication for services
vault auth enable approle
vault write auth/approle/role/ingestion-service \
    policies=vector-encrypt \
    token_ttl=1h
```

### 2. Rate Limiting

Prevent **Mean Estimation Attacks** by limiting encryption requests:

```bash
vault write sys/quotas/rate-limit/vector-encrypt \
    path="vector/encrypt/vector" \
    rate=100
```

### 3. Memory Locking

Ensure `disable_mlock = false` in your Vault config to prevent the matrix from being swapped to disk.

### 4. Monitoring

The plugin logs encryption requests (without vector content):

```
[INFO]  vector encryption request: dimension=1536 client_id=hvs.xxx
```

---

## 📁 Project Structure

```
vault-plugin-secrets-vector-dpe/
├── cmd/
│   └── vault-plugin-secrets-vector-dpe/
│       └── main.go              # Plugin entry point
├── internal/
│   └── plugin/
│       ├── backend.go           # Backend factory, caching, lifecycle
│       ├── config.go            # config/rotate endpoint
│       ├── encrypt.go           # encrypt/vector endpoint
│       ├── matrix_utils.go      # Orthogonal matrix & noise generation
│       └── *_test.go            # Unit tests
├── scripts/
│   ├── validate_sap.py          # SAP scheme validation
│   ├── validate_hardening.py    # Security hardening tests
│   └── verify_release.py        # Release verification (UAT)
├── .github/
│   └── workflows/
│       └── test.yml             # CI pipeline
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── SECURITY.md
└── LICENSE
```

---

## 🧪 Testing

```bash
# Run unit tests
make test

# Run linter
make lint

# Run full validation suite
make validate
```

---

## 🔧 Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `vector dimension X does not match configured dimension Y` | Input vector size mismatch | Reconfigure with correct dimension or fix input |
| `scaling_factor must be positive` | Invalid parameter | Use a positive value for scaling_factor |
| `dimension exceeds maximum allowed 8192` | DoS protection triggered | Use dimension ≤ 8192 |
| `mlock` errors | Memory locking disabled | Enable mlock in Vault config or run with sufficient privileges |

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE).

---

## 🔐 Security

See [SECURITY.md](SECURITY.md) for:
- Threat model
- Security assumptions and limitations
- Responsible disclosure policy
