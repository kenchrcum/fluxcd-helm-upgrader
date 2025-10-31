#!/usr/bin/env python3
"""Test runner script for FluxCD Helm Upgrader."""

import sys
import subprocess
import os


def run_tests():
    """Run the test suite."""
    print("🧪 Running FluxCD Helm Upgrader tests...")
    
    # Change to project directory
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)
    
    # Run pytest
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/",
        "-v",
        "--tb=short",
        "--cov=main",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-fail-under=34"
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print("✅ All tests passed!")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"❌ Tests failed with exit code {e.returncode}")
        return e.returncode


if __name__ == "__main__":
    sys.exit(run_tests())
