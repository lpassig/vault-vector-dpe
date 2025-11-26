import hvac
import numpy as np
import sys
import time

# Configuration
VAULT_URL = 'http://127.0.0.1:8200'
VAULT_TOKEN = 'root'
MOUNT_POINT = 'he-vector'
PLUGIN_NAME = 'vector-dpe'

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
            print(f"⚠️  Secrets engine not found at {MOUNT_POINT}/. Attempting to enable...")
            # This assumes the plugin is already registered
            client.sys.enable_secrets_engine(backend_type=PLUGIN_NAME, path=MOUNT_POINT)
    except Exception as e:
        print(f"⚠️  Error checking/enabling plugin: {e}")

    # --- Test A: DoS Protection (Bounds Check) ---
    print(f"\n🛡️ [Test A] DoS Protection (Dimension Limit)")
    
    # 1. Attempt Oversized Dimension (Max is 8192)
    oversized_dim = 100000
    try:
        client.write(f'{MOUNT_POINT}/config/rotate', dimension=oversized_dim)
        print(f"   ❌ FAIL: Server allowed dimension {oversized_dim} (Should have rejected)")
        sys.exit(1)
    except hvac.exceptions.InvalidRequest as e:
        print(f"   ✅ PASS: Server rejected dimension {oversized_dim} with 400 Bad Request")
    except Exception as e:
        print(f"   ✅ PASS: Server rejected dimension {oversized_dim} with error: {type(e).__name__}")

    # 2. Reset to Valid Dimension
    valid_dim = 1536 # Standard dimension for stable statistics
    try:
        client.write(f'{MOUNT_POINT}/config/rotate', 
                     dimension=valid_dim, 
                     scaling_factor=10.0, 
                     approximation_factor=2.0)
        print(f"   ✅ PASS: Server accepted valid dimension {valid_dim}")
    except Exception as e:
        print(f"   ❌ FAIL: Server rejected valid dimension {valid_dim}: {e}")
        sys.exit(1)


    # --- Test B: Input Validation (NaN/Inf) ---
    print(f"\n🛡️ [Test B] Input Validation (NaN/Inf)")
    
    bad_vector_nan = [0.1] * valid_dim
    bad_vector_nan[0] = float('nan')
    
    bad_vector_inf = [0.1] * valid_dim
    bad_vector_inf[0] = float('inf')

    # Check NaN
    try:
        client.write(f'{MOUNT_POINT}/encrypt/vector', vector=bad_vector_nan)
        print(f"   ❌ FAIL: Server accepted NaN value")
        sys.exit(1)
    except Exception as e:
        print(f"   ✅ PASS: Server rejected NaN value")

    # Check Inf
    try:
        client.write(f'{MOUNT_POINT}/encrypt/vector', vector=bad_vector_inf)
        print(f"   ❌ FAIL: Server accepted Infinity value")
        sys.exit(1)
    except Exception as e:
        print(f"   ✅ PASS: Server rejected Infinity value")


    # --- Test C: Probabilistic Noise (Regression Check) ---
    print(f"\n🧪 [Test C] Probabilistic Noise (Regression Check)")
    
    vec_c = np.random.normal(0, 1, valid_dim).tolist()
    
    try:
        resp_1 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_c)
        resp_2 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_c)
        
        c1 = np.array(resp_1['data']['ciphertext'])
        c2 = np.array(resp_2['data']['ciphertext'])
        
        if not np.allclose(c1, c2):
            print(f"   ✅ PASS: Ciphertexts are different (CryptoSource noise is active)")
        else:
            print(f"   ❌ FAIL: Ciphertexts are identical (Deterministic encryption detected)")
            sys.exit(1)
    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)


    # --- Test D: Utility Regression (Math Check) ---
    print(f"\n🧪 [Test D] Utility Regression (Math Check)")
    
    # Generate similar vectors
    vec_a = np.random.normal(0, 1, valid_dim)
    vec_a = vec_a / np.linalg.norm(vec_a)
    
    noise = np.random.normal(0, 0.1, valid_dim)
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
        
        if drift < 0.1: # Strict check for regression
            print(f"   ✅ PASS: Matrix math is preserving distance correctly")
        else:
            print(f"   ❌ FAIL: Drift too large ({drift:.4f}) - Logic might be broken")
            sys.exit(1)

    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)

    print(f"\n🎉 ALL HARDENING CHECKS PASSED!")

if __name__ == "__main__":
    main()

