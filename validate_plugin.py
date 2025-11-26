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
# SAP Parameters (s=10, beta=2.0)
SCALING_FACTOR = 10.0
APPROXIMATION_FACTOR = 2.0

def main():
    # 1. Connect to Vault
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    
    if not client.is_authenticated():
        print(f"❌ Authentication failed: Unable to authenticate to {VAULT_URL}")
        sys.exit(1)
    
    print(f"✅ Connected to Vault at {VAULT_URL}")

    # 2. Enable Plugin (if needed)
    try:
        secrets_engines = client.sys.list_mounted_secrets_engines()['data']
        if f"{MOUNT_POINT}/" not in secrets_engines:
            print(f"🔄 Enabling '{PLUGIN_NAME}' at '{MOUNT_POINT}/'...")
            client.sys.enable_secrets_engine(
                backend_type=PLUGIN_NAME,
                path=MOUNT_POINT,
            )
            print(f"✅ Enabled secrets engine at {MOUNT_POINT}/")
        else:
            print(f"✅ Secrets engine already enabled at {MOUNT_POINT}/")
    except Exception as e:
        print(f"❌ Failed to enable secrets engine: {e}")
        sys.exit(1)

    # 3. Configure Dimension and SAP params
    print(f"⚙️  Configuring plugin (dim={DIMENSION}, s={SCALING_FACTOR}, beta={APPROXIMATION_FACTOR})...")
    try:
        client.write(f'{MOUNT_POINT}/config/rotate', 
                     dimension=DIMENSION, 
                     scaling_factor=SCALING_FACTOR, 
                     approximation_factor=APPROXIMATION_FACTOR)
        print(f"✅ Configuration successful")
    except Exception as e:
        print(f"❌ Failed to configure plugin: {e}")
        sys.exit(1)

    # 4. Generate Vectors (A and B)
    print(f"\n🎲 Generating random vectors (dim={DIMENSION})...")
    
    vec_a = np.random.normal(0, 1, DIMENSION)
    vec_a = vec_a / np.linalg.norm(vec_a) # Normalize
    
    noise = np.random.normal(0, 0.5, DIMENSION)
    vec_b = vec_a + noise
    vec_b = vec_b / np.linalg.norm(vec_b) # Normalize

    # 5. Calculate Plaintext Similarity
    sim_plain = np.dot(vec_a, vec_b)
    print(f"📊 Plaintext Cosine Similarity: {sim_plain:.8f}")

    # 6. Encrypt Vectors (Probabilistic Check)
    print(f"🔐 Encrypting vectors via Vault (checking probabilistic nature)...")
    try:
        # Encrypt A twice to prove it's probabilistic
        resp_a1 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_a.tolist())
        resp_a2 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_a.tolist())
        resp_b = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=vec_b.tolist())
        
        enc_a1 = np.array(resp_a1['data']['ciphertext'])
        enc_a2 = np.array(resp_a2['data']['ciphertext'])
        enc_b = np.array(resp_b['data']['ciphertext'])
        
        print(f"✅ Encryption complete")
        
        # Check 4: Probabilistic Encryption
        if not np.allclose(enc_a1, enc_a2):
             print(f"   • Probabilistic Check: ✅ PASS (C(A) != C(A') for same A)")
        else:
             print(f"   • Probabilistic Check: ❌ FAIL (Determininstic encryption detected!)")
             sys.exit(1)

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        sys.exit(1)

    # 7. Calculate Encrypted Similarity
    enc_a_norm = enc_a1 / np.linalg.norm(enc_a1)
    enc_b_norm = enc_b / np.linalg.norm(enc_b)
    
    sim_enc = np.dot(enc_a_norm, enc_b_norm)
    print(f"📊 Encrypted Cosine Similarity: {sim_enc:.8f}")

    # 8. Validations
    print(f"\n🔎 Validation Report:")
    drift = abs(sim_plain - sim_enc)
    print(f"   • Drift: {drift:.10f}")

    # Check 1: Utility (Approximate Similarity Preservation)
    # With SAP, drift is expected. Bound is roughly related to beta/norm.
    # For unit vectors, we expect high correlation but not perfect.
    if drift < 0.05: # 5% tolerance for approximate DPE
        print(f"   • Utility Check: ✅ PASS (Cosine similarity preserved within tolerance)")
    else:
        print(f"   • Utility Check: ❌ FAIL (Drift too high: {drift:.4f})")
        sys.exit(1)

    # Check 2: Privacy (Scrambling)
    dist = np.linalg.norm(vec_a - enc_a1)
    print(f"   • Distance (A vs EncA): {dist:.4f}")
    
    if dist > 0.1: 
        print(f"   • Privacy Check: ✅ PASS (Vector has moved significantly)")
    else:
        print(f"   • Privacy Check: ❌ FAIL (Vector hasn't changed enough)")
        sys.exit(1)

    print(f"\n🎉 ALL CHECKS PASSED!")

if __name__ == "__main__":
    main()
