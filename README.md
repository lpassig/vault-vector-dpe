# Vault Vector DPE (Distance-Preserving Encryption)

A **HashiCorp Vault Secrets Engine** that implements **Approximate Distance-Comparison-Preserving Encryption (DCPE)** for vector embeddings.

This plugin enables secure vector search (e.g., in Pinecone, Milvus, or Weaviate) by encrypting embeddings in a way that preserves their approximate relative distances. It implements the **Scale-And-Perturb (SAP)** scheme to providing strong resistance against Chosen-Plaintext Attacks (CPA) through probabilistic encryption.

## 🔑 Key Features

*   **Approximate Distance Preservation**: Encrypted vectors can still be searched using Cosine Similarity or Euclidean Distance with high accuracy.
*   **Probabilistic Encryption**: Unlike standard rotation, this plugin adds noise to every encryption operation. Encrypting the same vector twice yields different ciphertexts ($C_1 \neq C_2$), defeating simple frequency analysis.
*   **Tunable Security/Utility**: Configure the trade-off between search accuracy and cryptographic security using the `approximation_factor`.
*   **Stateless**: The encryption key (Orthogonal Matrix) is derived deterministically from a seed stored in Vault, requiring no large matrix storage.

---

## 📐 Architecture: Scale-And-Perturb (SAP)

The plugin uses the **SAP** scheme (similar to IronCore Alloy) to transform a plaintext vector $v$ into a ciphertext $C$:

$$
C = s \cdot Q \cdot v + \lambda_m
$$

Where:
*   **$Q$**: An Orthogonal Matrix ($Q^T Q = I$) derived from a secret seed. This rotates the vector in high-dimensional space.
*   **$s$**: A secret scaling factor (scalar).
*   **$\lambda_m$**: A **random noise vector** generated fresh for every request. It is sampled uniformly from a ball derived from the `approximation_factor` ($\beta$).

Because $\lambda_m$ is random, the encryption is **probabilistic**. An attacker cannot easily solve the linear system $C = Q \cdot v$ to recover $Q$ because the exact values are masked by noise.

---

## 🚀 Installation & Registration

### 1. Build the Plugin
Requires Go 1.21+.

```bash
cd plugins/
go build -o vault-vector-dpe .
```

### 2. Install into Vault
Move the binary to your Vault plugin directory (configured in your Vault server config).

```bash
# Example: /etc/vault/plugins or ~/.vault.d/plugins
mv vault-vector-dpe ~/.vault.d/plugins/
```

### 3. Calculate Checksum
Vault requires the SHA256 checksum of the binary for registration.

```bash
SHASUM=$(shasum -a 256 ~/.vault.d/plugins/vault-vector-dpe | cut -d " " -f1)
echo $SHASUM
```

### 4. Register & Enable
Register the plugin with the Vault server and enable the secrets engine.

```bash
# Register the plugin
vault plugin register \
    -sha256=$SHASUM \
    -command="vault-vector-dpe" \
    secret vector-dpe

# Enable the secrets engine at path 'vector/'
vault secrets enable -path=vector vector-dpe
```

---

## ⚙️ Configuration

Before you can encrypt vectors, you must initialize the engine by generating a seed and setting the SAP parameters.

**Endpoint:** `config/rotate`

### Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `dimension` | `int` | `1536` | Dimensionality of your embeddings (e.g., 1536 for OpenAI `text-embedding-3-small`). |
| `scaling_factor` | `float` | `1.0` | Scalar multiplier ($s$). Scales the magnitude of encrypted vectors. |
| `approximation_factor` | `float` | `5.0` | The Noise Factor ($\beta$). **Higher = More Secure** (more noise), but **Less Accurate** search. |

### Example: Initialize with High Security
```bash
vault write vector/config/rotate \
    dimension=1536 \
    scaling_factor=10.0 \
    approximation_factor=5.0
```

> **Note:** Calling this endpoint again **Rotates the Key**. It generates a new random seed, effectively invalidating all previously encrypted data (unless you re-index).

---

## 🔒 Usage

### Encrypt a Vector
Send a JSON array of floats to the `encrypt/vector` endpoint.

**Request:**
```bash
vault write -format=json vector/encrypt/vector vector='[0.1, 0.5, -0.2, ...]'
```

**Response:**
```json
{
  "request_id": "8f2b...",
  "data": {
    "ciphertext": [
      1.24501,
      -0.55210,
      0.00321,
      ...
    ]
  }
}
```

### Probabilistic Check
If you run the above command twice with the **exact same input**, you will get **different ciphertexts**.
*   $C_1 \neq C_2$
*   However, $dist(C_1, C_2)$ will be small (within the noise margin).

---

## 🛡️ Production Hardening

### 1. Strict Access Control (AppRole)
Treat the `encrypt/vector` endpoint as a **Signing Oracle**. If an attacker can encrypt arbitrary vectors, they may attempt statistical attacks to estimate the matrix $Q$.
*   **DO NOT** allow human users access to this path.
*   **ONLY** allow trusted ingestion services (e.g., your Vector DB loader) via **AppRole** or **Kubernetes Auth**.

### 2. Rate Limiting (Crucial)
To prevent **Mean Estimation Attacks** (where an attacker encrypts the same vector thousands of times to average out the noise $\lambda_m$), you **must** apply a rate limit.

```bash
# Limit to 50 requests/second
vault write sys/quotas/rate-limit/vector-encrypt \
    path=vector/encrypt/vector \
    rate=50
```

### 3. Memory Hygiene
Ensure your Vault server has `disable_mlock = false` (default) in its configuration. The orthogonal matrix $Q$ is large (~18MB for dim=1536) and resides in memory; `mlock` prevents it from being swapped to disk.

---

## 🔧 Troubleshooting

**Error: `vector dimension X does not match configured dimension Y`**
*   **Cause:** You are trying to encrypt a vector (e.g., size 768) that doesn't match the configured dimension (e.g., 1536).
*   **Fix:** Re-configure the engine using `config/rotate` with the correct dimension, or fix your input data.

**Error: `internal error` during `config/rotate`**
*   **Cause:** Usually due to an invalid float format or zero/negative dimension.
*   **Fix:** Ensure `scaling_factor` and `approximation_factor` are valid floats.

**Performance Latency**
*   **Cause:** Generating a 1536x1536 orthogonal matrix takes time (~100ms-500ms).
*   **Fix:** The matrix is **cached** in memory. The first request after a rotation or restart will be slow; subsequent requests are fast matrix multiplications.

