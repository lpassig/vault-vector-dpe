# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Threat Model

The `vault-vector-dpe` plugin implements **Approximate Distance-Preserving Encryption (DCPE)**. This scheme provides a trade-off between security and utility (searchability).

### Security Guarantees
1.  **Ciphertext Indistinguishability (CPA-Security):** The plugin uses the **Scale-And-Perturb (SAP)** scheme. This adds probabilistic noise ($\lambda_m$) to the rotated vector. Encrypting the same plaintext twice yields different ciphertexts ($C_1 \neq C_2$), resisting simple frequency analysis and Chosen-Plaintext Attacks (CPA) better than deterministic rotation alone.
2.  **Key Protection:** The secret encryption key (Orthogonal Matrix $Q$) is derived from a 32-byte seed stored securely in Vault. The matrix is generated in memory and never persisted to disk.
3.  **Memory Hygiene:** Sensitive data (matrix, intermediate buffers) is zeroed out in memory when rotating keys or returning buffers to the pool.

### Limitations & Assumptions
*   **Approximate Security:** This is **not** generic encryption (like AES-GCM). The encryption is designed to *leak* distance information. An attacker with access to enough plaintext-ciphertext pairs and the ability to measure distances might be able to approximate the transformation matrix.
*   **Usage Constraint:** This plugin is intended for **vector embeddings only**. Do not use it to encrypt PII, passwords, or sensitive text directly.
*   **Trust Model:** The Vault server and the client (Application) are trusted. The "Attacker" is assumed to be an observer of the Vector Database (where ciphertexts are stored).

## Hardening & Best Practices

### 1. Access Control
*   **Strict RBAC:** Limit access to the `encrypt/vector` endpoint. Only the ingestion pipeline (Loader) should have permission to encrypt.
*   **No Human Access:** Do not allow human operators to query the encryption endpoint to prevent manual chosen-plaintext attacks.

### 2. Resource Quotas
*   **Rate Limiting:** Apply Vault Rate Limits (`sys/quotas/rate-limit`) to the `encrypt/vector` path to prevent high-volume statistical attacks.
*   **Dimension Limits:** The plugin enforces a hard limit of 8192 dimensions. Ensure your Vault server has sufficient RAM (matrix size scales with $N^2$).

### 3. Infrastructure
*   **Memory Locking:** Ensure `mlock` is enabled in Vault configuration to prevent the large orthogonal matrix from being swapped to disk.
*   **Audit Logging:** Enable Vault Audit Devices to track all encryption requests.

## Reporting a Vulnerability

Please report sensitive security issues via email to the maintainer or open a Draft Security Advisory in the repository. Do **not** open a public issue for critical vulnerabilities.
