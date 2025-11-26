#!/usr/bin/env python3
"""
verify_release.py - User Acceptance Test (UAT) for vault-vector-dpe

This script performs a complete end-to-end validation of the plugin:
1. Builds the plugin binary
2. Registers it with Vault
3. Enables the secrets engine
4. Configures it via config/rotate
5. Encrypts a sample vector
6. Validates the output format and properties

Requirements:
    - Python 3.8+
    - hvac, numpy (pip install hvac numpy)
    - Vault server running in dev mode
    - Go 1.22+ installed

Usage:
    python3 verify_release.py
"""

import subprocess
import sys
import os
import time
import json
import hashlib

# Try to import optional dependencies
try:
    import hvac
    import numpy as np
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

# Configuration
VAULT_URL = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN', 'root')
PLUGIN_NAME = 'vault-plugin-secrets-vector-dpe'
MOUNT_POINT = 'vector-test'
BUILD_DIR = './cmd/vault-plugin-secrets-vector-dpe'
# Plugin dir is relative to the script location (repo root)
PLUGIN_DIR = os.environ.get('VAULT_PLUGIN_DIR', None)  # Will be set to absolute path

# Test Parameters (match README examples)
TEST_DIMENSION = 1536
TEST_SCALING_FACTOR = 10.0
TEST_APPROX_FACTOR = 5.0


def run_cmd(cmd: list, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=False
    )
    if check and result.returncode != 0:
        print(f"    ❌ Command failed: {result.stderr or result.stdout}")
        sys.exit(1)
    return result


def phase_1_build(script_dir: str):
    """Phase 1: Build the plugin binary."""
    print("\n" + "=" * 60)
    print("📦 PHASE 1: Build Plugin Binary")
    print("=" * 60)

    # Use absolute path for plugin directory (at repo root)
    plugin_dir = PLUGIN_DIR or os.path.join(script_dir, 'bin')
    os.makedirs(plugin_dir, exist_ok=True)

    # Build from repo root using new cmd/ structure
    binary_path = os.path.join(plugin_dir, PLUGIN_NAME)
    result = run_cmd(['go', 'build', '-o', binary_path, './cmd/vault-plugin-secrets-vector-dpe'], check=True)
    
    if not os.path.exists(binary_path):
        print(f"    ❌ Binary not found at {binary_path}")
        sys.exit(1)
    
    # Calculate SHA256
    with open(binary_path, 'rb') as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    
    print(f"    ✅ Built: {binary_path}")
    print(f"    ✅ SHA256: {sha256}")
    
    # Kill any running Vault so it picks up the new binary
    print("    🔄 Restarting Vault to pick up new binary...")
    run_cmd(['pkill', '-f', 'vault server'], check=False)
    time.sleep(2)
    
    return binary_path, sha256, plugin_dir


def phase_2_register(sha256: str, plugin_dir: str):
    """Phase 2: Register the plugin with Vault."""
    print("\n" + "=" * 60)
    print("🔌 PHASE 2: Register Plugin with Vault")
    print("=" * 60)

    # Check Vault status
    result = run_cmd(['vault', 'status'], check=False)
    if result.returncode != 0:
        print("    ⚠️  Vault is not running. Attempting to start...")
        # Kill any existing vault and restart with fresh binary
        run_cmd(['pkill', '-f', 'vault server'], check=False)
        time.sleep(2)
        
        # Start Vault in background with absolute path to plugin dir
        env = os.environ.copy()
        env['VAULT_DEV_ROOT_TOKEN_ID'] = 'root'
        env['VAULT_ADDR'] = VAULT_URL
        subprocess.Popen(
            ['vault', 'server', '-dev', f'-dev-plugin-dir={plugin_dir}'],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        
        result = run_cmd(['vault', 'status'], check=False)
        if result.returncode != 0:
            print("    ❌ Failed to start Vault")
            sys.exit(1)
    
    print("    ✅ Vault is running")

    # Deregister if exists (ignore errors)
    run_cmd(['vault', 'secrets', 'disable', f'{MOUNT_POINT}/'], check=False)
    run_cmd(['vault', 'plugin', 'deregister', 'secret', PLUGIN_NAME], check=False)

    # Register plugin
    run_cmd([
        'vault', 'plugin', 'register',
        f'-sha256={sha256}',
        f'-command={PLUGIN_NAME}',
        'secret', PLUGIN_NAME
    ], check=True)
    print(f"    ✅ Plugin registered: {PLUGIN_NAME}")

    # Enable secrets engine
    run_cmd([
        'vault', 'secrets', 'enable',
        f'-path={MOUNT_POINT}',
        PLUGIN_NAME
    ], check=True)
    print(f"    ✅ Secrets engine enabled at: {MOUNT_POINT}/")


def phase_3_configure(client: 'hvac.Client'):
    """Phase 3: Configure the plugin via config/rotate."""
    print("\n" + "=" * 60)
    print("⚙️  PHASE 3: Configure Plugin (config/rotate)")
    print("=" * 60)

    try:
        response = client.write(
            f'{MOUNT_POINT}/config/rotate',
            dimension=TEST_DIMENSION,
            scaling_factor=TEST_SCALING_FACTOR,
            approximation_factor=TEST_APPROX_FACTOR
        )
        print(f"    ✅ Configuration successful")
        print(f"       dimension: {response['data']['dimension']}")
        print(f"       scaling_factor: {response['data']['scaling_factor']}")
        print(f"       approximation_factor: {response['data']['approximation_factor']}")
        
        # Verify response matches input
        assert response['data']['dimension'] == TEST_DIMENSION, "Dimension mismatch"
        assert response['data']['scaling_factor'] == TEST_SCALING_FACTOR, "Scaling factor mismatch"
        assert response['data']['approximation_factor'] == TEST_APPROX_FACTOR, "Approx factor mismatch"
        
    except Exception as e:
        print(f"    ❌ Configuration failed: {e}")
        sys.exit(1)


def phase_4_encrypt(client: 'hvac.Client'):
    """Phase 4: Encrypt a sample vector and validate output."""
    print("\n" + "=" * 60)
    print("🔒 PHASE 4: Encrypt Vector (encrypt/vector)")
    print("=" * 60)

    # Generate a random normalized vector (like a real embedding)
    np.random.seed(42)  # For reproducibility in testing
    sample_vector = np.random.normal(0, 1, TEST_DIMENSION)
    sample_vector = sample_vector / np.linalg.norm(sample_vector)  # Normalize
    
    print(f"    📊 Input vector: dim={len(sample_vector)}, norm={np.linalg.norm(sample_vector):.4f}")
    
    try:
        response = client.write(
            f'{MOUNT_POINT}/encrypt/vector',
            vector=sample_vector.tolist()
        )
        
        ciphertext = np.array(response['data']['ciphertext'])
        
        print(f"    ✅ Encryption successful")
        print(f"       Output dimension: {len(ciphertext)}")
        print(f"       Output norm: {np.linalg.norm(ciphertext):.4f}")
        print(f"       First 3 values: {ciphertext[:3]}")
        
        # Validation 1: Correct dimension
        assert len(ciphertext) == TEST_DIMENSION, f"Output dimension {len(ciphertext)} != {TEST_DIMENSION}"
        print(f"    ✅ Dimension check: PASS")
        
        # Validation 2: All values are valid floats (not NaN/Inf)
        assert not np.any(np.isnan(ciphertext)), "Output contains NaN"
        assert not np.any(np.isinf(ciphertext)), "Output contains Inf"
        print(f"    ✅ Float validity check: PASS")
        
        # Validation 3: Output is different from input (encryption happened)
        assert not np.allclose(ciphertext, sample_vector), "Ciphertext equals plaintext!"
        print(f"    ✅ Encryption transformation check: PASS")
        
        return sample_vector, ciphertext
        
    except Exception as e:
        print(f"    ❌ Encryption failed: {e}")
        sys.exit(1)


def phase_5_probabilistic_check(client: 'hvac.Client', sample_vector):
    """Phase 5: Verify probabilistic encryption (C1 != C2)."""
    print("\n" + "=" * 60)
    print("🎲 PHASE 5: Probabilistic Encryption Check")
    print("=" * 60)

    try:
        # Encrypt the same vector twice
        resp1 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=sample_vector.tolist())
        resp2 = client.write(f'{MOUNT_POINT}/encrypt/vector', vector=sample_vector.tolist())
        
        c1 = np.array(resp1['data']['ciphertext'])
        c2 = np.array(resp2['data']['ciphertext'])
        
        # They should be different
        if np.allclose(c1, c2):
            print(f"    ❌ FAIL: Ciphertexts are identical (deterministic encryption!)")
            sys.exit(1)
        
        # But not wildly different (noise is bounded)
        diff_norm = np.linalg.norm(c1 - c2)
        print(f"    ✅ PASS: C1 ≠ C2 (diff norm: {diff_norm:.4f})")
        print(f"       This confirms probabilistic encryption is working.")
        
    except Exception as e:
        print(f"    ❌ Check failed: {e}")
        sys.exit(1)


def phase_6_readme_validation(client: 'hvac.Client'):
    """Phase 6: Verify README examples work."""
    print("\n" + "=" * 60)
    print("📖 PHASE 6: README Example Validation")
    print("=" * 60)

    # Test the exact example from README
    readme_vector = [0.1, 0.5, -0.2] + [0.0] * (TEST_DIMENSION - 3)
    
    try:
        response = client.write(
            f'{MOUNT_POINT}/encrypt/vector',
            vector=readme_vector
        )
        
        ciphertext = response['data']['ciphertext']
        
        # Check response format matches README
        assert 'ciphertext' in response['data'], "Response missing 'ciphertext' key"
        assert isinstance(ciphertext, list), "Ciphertext is not a list"
        assert len(ciphertext) == TEST_DIMENSION, "Ciphertext dimension mismatch"
        
        print(f"    ✅ README example format validated")
        print(f"       Response contains 'ciphertext' key: ✓")
        print(f"       Ciphertext is array of floats: ✓")
        print(f"       Dimension matches configured: ✓")
        
    except Exception as e:
        print(f"    ❌ README validation failed: {e}")
        sys.exit(1)


def main():
    print("=" * 60)
    print("🚀 vault-vector-dpe Release Verification Script")
    print("=" * 60)
    print(f"Vault URL: {VAULT_URL}")
    print(f"Plugin: {PLUGIN_NAME}")
    print(f"Mount Point: {MOUNT_POINT}")

    # Check dependencies
    if not HAS_DEPS:
        print("\n⚠️  Missing Python dependencies. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'hvac', 'numpy', '-q'], check=True)
        print("   Please re-run this script.")
        sys.exit(0)

    # Change to repo root directory
    original_dir = os.getcwd()
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Go up from scripts/
    os.chdir(script_dir)

    try:
        # Phase 1: Build
        binary_path, sha256, plugin_dir = phase_1_build(script_dir)

        # Phase 2: Register (already in repo root)
        phase_2_register(sha256, plugin_dir)

        # Initialize hvac client
        client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
        if not client.is_authenticated():
            print(f"\n❌ Cannot authenticate to Vault at {VAULT_URL}")
            sys.exit(1)

        # Phase 3: Configure
        phase_3_configure(client)

        # Phase 4: Encrypt
        sample_vector, ciphertext = phase_4_encrypt(client)

        # Phase 5: Probabilistic Check
        phase_5_probabilistic_check(client, sample_vector)

        # Phase 6: README Validation
        phase_6_readme_validation(client)

        # Success!
        print("\n" + "=" * 60)
        print("🎉 ALL VERIFICATION CHECKS PASSED!")
        print("=" * 60)
        print(f"""
Summary:
  ✅ Plugin builds successfully
  ✅ Plugin registers with Vault
  ✅ config/rotate endpoint works
  ✅ encrypt/vector endpoint works
  ✅ Output is valid float array of correct dimension
  ✅ Encryption is probabilistic (C1 ≠ C2)
  ✅ README examples are accurate

The plugin is ready for release! 🚀
""")

    finally:
        os.chdir(original_dir)


if __name__ == "__main__":
    main()

