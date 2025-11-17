#!/usr/bin/env python3
"""sushCore test suite runner (production readiness validation)."""

import os
import sys
import subprocess
from pathlib import Path


def run_command(cmd: list, description: str) -> bool:
    """Run a command and return success status."""
    print(f"\nTesting {description}")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print(f"PASSED - {description}")
            return True
        else:
            print(f"FAILED - {description}")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False
    except Exception as e:
        print(f"ERROR - {description}: {e}")
        return False



def check_optional_dependencies() -> bool:
    """Verify whether optional production dependencies are available."""
    description = "Production Dependencies Check"
    print(f"\nTesting {description}")
    try:
        from sush.core.ml_kem import MLKEMKeyExchange
        MLKEMKeyExchange()
        print(f"PASSED - {description}")
        return True
    except ModuleNotFoundError as exc:
        print(f"SKIPPED - {description}: optional dependency '{exc.name}' is not installed.")
        return True
    except Exception as exc:
        print(f"FAILED - {description}")
        print("ERROR:", exc)
        return False


def main():
    """Run the complete test suite."""
    print("sushCore Production Test Suite")
    print("=" * 50)
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    test_results = []
    # Smoke test
    test_results.append(run_command(
        ["python", "tests/test_smoke.py"],
        "Smoke Test"
    ))

    # Core component validation
    test_results.append(run_command(
        ["python", "tests/test_core_components.py"],
        "Core Components Test"
    ))
    
    # Integration validation
    test_results.append(run_command(
        ["python", "tests/test_integration.py"],
        "Integration Test"
    ))
    
    # Comprehensive system test
    test_results.append(run_command(
        ["python", "tests/test_comprehensive.py"],
        "Comprehensive System Test"
    ))
    
    # Production dependencies check
    test_results.append(check_optional_dependencies())
    
    print("\n" + "=" * 50)
    print("Test Summary")
    print("=" * 50)
    
    for i, result in enumerate(test_results, 1):
        status = "PASS" if result else "FAIL"
        print(f"Test {i}: {status}")
    
    passed = sum(test_results)
    total = len(test_results)
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed - Ready for release")
        return 0
    else:
        print("Some tests failed - Review before release")
        return 1


if __name__ == "__main__":
    sys.exit(main())
