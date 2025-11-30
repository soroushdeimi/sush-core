#!/usr/bin/env python3
"""Quick test to verify benchmark scripts work."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
from tests.run_benchmarks import BenchmarkRunner

async def test():
    print("Starting quick benchmark test...")
    runner = BenchmarkRunner()
    
    try:
        print("Running Experiment A (Crypto Overhead)...")
        await runner.experiment_a_crypto_overhead()
        print(f"Experiment A completed. Results: {len(runner.results)} entries")
        
        print("\nSaving results...")
        runner.save_results()
        print("Results saved successfully!")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test())
    sys.exit(0 if result else 1)

