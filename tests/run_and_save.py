#!/usr/bin/env python3
"""Run benchmarks and save output to file."""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.run_benchmarks import main

if __name__ == "__main__":
    # Redirect output to file
    output_file = Path("tests/data/benchmark_output.txt")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        # Redirect stdout and stderr
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = f
        sys.stderr = f
        
        try:
            print("=" * 60)
            print("sushCore Benchmark Suite - Output Log")
            print("=" * 60)
            asyncio.run(main())
        except Exception as e:
            import traceback
            print(f"ERROR: {e}")
            traceback.print_exc()
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
    
    print(f"Benchmark completed. Output saved to: {output_file}")

