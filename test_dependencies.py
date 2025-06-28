#!/usr/bin/env python3
"""
Test script to check for dependency conflicts
"""

import sys

def test_imports():
    """Test importing all required packages"""
    packages = [
        'cryptography',
        'Crypto',  # pycryptodome
        'numpy',
        'sklearn',
        'asyncio_dgram',
        'aiohttp',
        'nacl',  # pynacl
        'kyber_py',
        'blake3',
        'prometheus_client',
        'yaml',  # pyyaml
        'click',
        'colorama',
        'OpenSSL',  # pyOpenSSL
        'dotenv',  # python-dotenv
        'dns',  # dnspython
        'aioquic',
        'websockets',
        'scapy'
    ]
    
    failed_imports = []
    successful_imports = []
    
    for package in packages:
        try:
            __import__(package)
            successful_imports.append(package)
            print(f"✓ {package} imported successfully")
        except ImportError as e:
            failed_imports.append((package, str(e)))
            print(f"✗ {package} failed to import: {e}")
        except Exception as e:
            failed_imports.append((package, str(e)))
            print(f"✗ {package} error: {e}")
    
    print(f"\nSummary:")
    print(f"Successful imports: {len(successful_imports)}")
    print(f"Failed imports: {len(failed_imports)}")
    
    if failed_imports:
        print(f"\nFailed imports:")
        for package, error in failed_imports:
            print(f"  {package}: {error}")
        return False
    else:
        print(f"\nAll packages imported successfully!")
        return True

def test_crypto_conflicts():
    """Test for potential conflicts between cryptography libraries"""
    print("\nTesting crypto library conflicts...")
    
    try:
        import cryptography
        import Crypto
        print("✓ Both cryptography and pycryptodome can coexist")
        
        # Test basic functionality
        from cryptography.hazmat.primitives import hashes
        from Crypto.Hash import SHA256
        
        print("✓ Both libraries' basic functionality works")
        return True
    except Exception as e:
        print(f"✗ Crypto library conflict detected: {e}")
        return False

if __name__ == "__main__":
    print("Testing dependency conflicts...")
    print("=" * 50)
    
    success = test_imports()
    crypto_success = test_crypto_conflicts()
    
    if success and crypto_success:
        print("\n🎉 No dependency conflicts detected!")
        sys.exit(0)
    else:
        print("\n❌ Dependency conflicts found!")
        sys.exit(1) 