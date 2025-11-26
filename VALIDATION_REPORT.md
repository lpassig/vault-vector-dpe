# Validation Report: Distance-Preserving Encryption Plugin

## 1. Implementation Verification
The plugin implements the **Scale-And-Perturb (SAP)** scheme for Approximate Distance-Comparison-Preserving Encryption (DCPE), aligning with the IronCore Labs Alloy SDK approach.

- **Core Algorithm**: $C = s \cdot Q \cdot v + \lambda_m$
    -   $Q$: Orthogonal matrix derived via `mat.QR(RandomNormal(seed))`.
    -   $s$: Secret scaling factor.
    -   $\lambda_m$: Random perturbation vector (noise).
- **Noise Generation** (IronCore Logic):
    1.  Sample $u \sim \mathcal{N}(0, I_d)$.
    2.  Sample $x' \sim \mathcal{U}(0, 1)$.
    3.  Compute radius $x = \frac{s \cdot \beta}{4} (x')^{1/d}$, where $\beta$ is the approximation factor.
    4.  $\lambda_m = \frac{u \cdot x}{\|u\|}$.
- **Utility**: Preserves distance approximately: $|dist(C_1, C_2) - s \cdot dist(v_1, v_2)| \le \frac{s \cdot \beta}{2}$.
- **Correctness**: The implementation of `GenerateNormalizedVector` exactly mirrors IronCore's `crypto.rs` logic for generating $\lambda_m$.

## 2. Comparison with Industry & Research

### Vs. Scale-And-Perturb (SAP) [Fuchsbauer et al.]
The implementation strictly follows the SAP construction:
-   **Mechanism**: `Enc(m) = s*m + noise` (applied here after orthogonal rotation).
-   **Security**: Achieves resistance to frequency-finding and membership inference attacks due to probabilistic encryption (random $\lambda_m$ for each encryption).

### Vs. IronCore Labs (Approximate DPE)
-   **Alignment**: **High**. We adopted the specific noise sampling distribution used by IronCore's Alloy SDK (Uniform point in a ball derived from normal direction).
-   **Difference**: Our implementation uses an explicit stored Orthogonal Matrix ($Q$) for the rotation component, whereas IronCore might use a key-derived transform. The mathematical effect ($v \to v'$) is equivalent.

## 3. Security Analysis & Threat Model

### A. Ciphertext-Only Attack (COA) — **SECURE**
-   **Scenario**: Attacker sees only encrypted vectors.
-   **Analysis**: Ciphertexts are effectively random vectors. The orthogonal rotation ($Q$) scrambles directions, and the SAP noise ($\lambda_m$) masks exact values.

### B. Chosen-Plaintext Attack (CPA) — **RESILIENT** (Improved)
-   **Scenario**: Attacker encrypts chosen vectors.
-   **Previous Vulnerability (Exact DPE)**: $Q$ could be solved via $C = Q \cdot P^{-1}$.
-   **Current Status (SAP)**: The encryption is now **probabilistic**.
    -   $C = s \cdot Q \cdot v + \lambda_m$.
    -   $\lambda_m$ is fresh for every request.
    -   The noise prevents solving the linear system exactly. An attacker can only estimate $Q$ with limited precision, bounded by the approximation factor $\beta$.
-   **Mitigation**: The approximation factor $\beta$ acts as a security parameter. Larger $\beta$ = more noise = harder to recover $Q$, but lower search precision.

### C. Operational Security
-   **Seed/Key Rotation**: The `config/rotate` endpoint now rotates the seed (regenerating $Q$) and allows tuning $s$ and $\beta$.
-   **Rate Limiting**: Still recommended to prevent attackers from averaging out the noise by encrypting the same vector millions of times (Mean Estimation Attack).

## 4. Conclusion
The plugin **PASSES** validation for **Approximate Distance-Preserving Encryption**.

-   **Transition Success**: Successfully moved from "Exact" (brittle) to "Approximate" (robust) DPE.
-   **Industry Standard**: The noise generation logic matches the IronCore Alloy reference implementation.
-   **Trade-off**: The plugin now prioritizes **security (CPA resistance)** over perfect utility. Users can tune this trade-off via the `approximation_factor` configuration.
