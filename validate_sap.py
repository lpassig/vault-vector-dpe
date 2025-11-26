import hvac
import numpy as np
import sys
import time

# Configuration
VAULT_URL = 'http://127.0.0.1:8200'
VAULT_TOKEN = 'root'
MOUNT_POINT = 'he-vector'
PLUGIN_NAME = 'vector-dpe'
DIMENSION = 1536
# Test Parameters
TEST_SCALING_FACTOR = 10.0
TEST_APPROX_FACTOR = 2.0

def main():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    
    if not client.is_authenticated():
        print(f"❌ Authentication failed: Unable to authenticate to {VAULT_URL}")
        sys.exit(1)
    
    print(f"✅ Connected to Vault at {VAULT_URL}")

    # Ensure Plugin Enabled
    try:
        secrets_engines = client.sys.list_mounted_secrets_engines()['data']
        if f"{MOUNT_POINT}/" not in secrets_engines:
            client.sys.enable_secrets_engine(
                backend_type=PLUGIN_NAME,
                path=MOUNT_POINT,
            )
            print(f"✅ Enabled secrets engine at {MOUNT_POINT}/")
    except Exception as e:
        print(f"⚠️  Assuming plugin enabled or error checking: {e}")

    # Configure Plugin
    print(f"⚙️  Configuring plugin (dim={DIMENSION}, s={TEST_SCALING_FACTOR}, beta={TEST_APPROX_FACTOR})...")
    try:
        client.write(f'{MOUNT_POINT}/config/rotate', 
                     dimension=DIMENSION, 
                     scaling_factor=TEST_SCALING_FACTOR, 
                     approximation_factor=TEST_APPROX_FACTOR)
        print(f"✅ Configuration successful")
    except Exception as e:
        print(f"❌ Failed to configure plugin: {e}")
        sys.exit(1)

    # --- Check 1: Probabilistic Encryption ---
    print(f"\n🧪 [Check 1] Probabilistic Encryption (CPA Resistance)")
    vec_prob = np.random.normal(0, 1, DIMENSION)
    
    try:
        resp_1 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_prob.tolist())
        resp_2 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_prob.tolist())
        
        c1 = np.array(resp_1['data']['ciphertext'])
        c2 = np.array(resp_2['data']['ciphertext'])
        
        if not np.allclose(c1, c2):
            print(f"   ✅ PASS: Ciphertexts are different (Noise is active)")
        else:
            print(f"   ❌ FAIL: Ciphertexts are identical (Deterministic encryption detected)")
            sys.exit(1)
    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)

    # --- Check 2: Approximate Utility (Drift) ---
    print(f"\n🧪 [Check 2] Approximate Utility (Drift Analysis)")
    
    # Generate similar vectors
    vec_a = np.random.normal(0, 1, DIMENSION)
    vec_a = vec_a / np.linalg.norm(vec_a)
    
    noise = np.random.normal(0, 0.2, DIMENSION)
    vec_b = vec_a + noise
    vec_b = vec_b / np.linalg.norm(vec_b)
    
    sim_plain = np.dot(vec_a, vec_b)
    
    try:
        resp_a = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_a.tolist())
        resp_b = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_b.tolist())
        
        enc_a = np.array(resp_a['data']['ciphertext'])
        enc_b = np.array(resp_b['data']['ciphertext'])
        
        # Normalize ciphertext for Cosine Similarity
        enc_a_norm = enc_a / np.linalg.norm(enc_a)
        enc_b_norm = enc_b / np.linalg.norm(enc_b)
        
        sim_cipher = np.dot(enc_a_norm, enc_b_norm)
        drift = abs(sim_plain - sim_cipher)
        
        print(f"   Plaintext Similarity: {sim_plain:.6f}")
        print(f"   Ciphertext Similarity: {sim_cipher:.6f}")
        print(f"   Drift: {drift:.6f}")
        
        if 0.0 < drift < 0.1:
            print(f"   ✅ PASS: Drift is small but non-zero (Approximate DPE)")
        elif drift == 0.0:
            print(f"   ❌ FAIL: Drift is exactly zero (Noise missing?)")
            sys.exit(1)
        else:
            print(f"   ❌ FAIL: Drift too large ({drift:.4f})")
            sys.exit(1)
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)

    # --- Check 3: Scaling Factor Compliance ---
    print(f"\n🧪 [Check 3] Scaling Factor Compliance (s={TEST_SCALING_FACTOR})")
    
    dist_plain = np.linalg.norm(vec_a - vec_b)
    dist_cipher = np.linalg.norm(enc_a - enc_b)
    
    # Expected: dist_cipher approx s * dist_plain
    # We allow a margin because of the noise addition
    ratio = dist_cipher / dist_plain
    expected_ratio = TEST_SCALING_FACTOR
    
    print(f"   Plaintext Distance: {dist_plain:.6f}")
    print(f"   Ciphertext Distance: {dist_cipher:.6f}")
    print(f"   Observed Scaling Ratio: {ratio:.4f} (Expected ~{expected_ratio})")
    
    # Allow 20% variance due to noise
    if abs(ratio - expected_ratio) < 0.2 * expected_ratio:
        print(f"   ✅ PASS: Scaling factor applied correctly")
    else:
        print(f"   ❌ FAIL: Scaling ratio mismatch")
        sys.exit(1)

    print(f"\n🎉 ALL SAP CHECKS PASSED!")

if __name__ == "__main__":
    main()

