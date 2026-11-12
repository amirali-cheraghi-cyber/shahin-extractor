"""
Shahin Extractor Integration Tests - Main Entry Point

This module provides a simple interface to run the complete test suite
for Shahin Extractor v9.3. It includes:
- Core functionality tests
- Regression tests
- Weakness fix integration tests
- End-to-end pipeline tests

Usage:
    python3 run_tests.py
    # or with pytest (if installed): python -m pytest tests/
"""

import sys
import unittest
from pathlib import Path

# Ensure the project root is in the Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import all test modules
from tests.test_core import CoreTests
from tests.test_regressions import (
    NVSStructuralParserTests,
    DeobfuscatorThresholdTests,
    CorrelationStrongThresholdTests,
    StaticAnalysisJSONRegexTests,
)
from tests.test_weakness_fixes import (
    DeobfuscatorCoverageTests,
    SerialWaitTimeTests,
    FilesystemUnpackParameterTests,
    RawFilenameCollisionTests,
)

# NOTE: tests/test_integration.py's `ShahinIntegrationTests` is not a
# unittest.TestCase subclass (no inheritance, and it instantiates adapters
# against a hardcoded "/dev/ttyUSB0" port), so it cannot be loaded or run
# through this runner yet. See CHANGELOG.md "Known issues".

def run_all_tests():
    """Run all test classes and return results."""
    # Create test suite
    suite = unittest.TestSuite()

    # Add tests from each test class
    test_classes = [
        CoreTests,
        NVSStructuralParserTests,
        DeobfuscatorThresholdTests,
        CorrelationStrongThresholdTests,
        StaticAnalysisJSONRegexTests,
        DeobfuscatorCoverageTests,
        SerialWaitTimeTests,
        FilesystemUnpackParameterTests,
        RawFilenameCollisionTests,
    ]

    for test_class in test_classes:
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(test_class))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result

if __name__ == "__main__":
    print("=" * 80)
    print("SHAHIN EXTRACTOR TEST SUITE - V9.3")
    print("=" * 80)
    print("\nTest modules included:")
    print("  • Core functionality (test_core.py)")
    print("  • Regression tests (test_regressions.py)")
    print("  • Weakness fixes (test_weakness_fixes.py)")
    print("\nNote: test_integration.py is not included here yet — see")
    print("CHANGELOG.md 'Known issues'.")
    print("\nRunning all tests...\n")

    result = run_all_tests()

    print("\n" + "=" * 80)
    print("TEST EXECUTION SUMMARY")
    print("=" * 80)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if hasattr(result, 'skipped'):
        print(f"Skipped: {len(result.skipped)}")

    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"\n{test}:")
            print(traceback)

    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"\n{test}:")
            print(traceback)

    success = result.wasSuccessful()
    print("\n" + "=" * 80)
    if success:
        print("✅ ALL TESTS PASSED - Shahin Extractor v9.3 is ready for deployment!")
    else:
        print("❌ SOME TESTS FAILED - Please review the failures above")
    print("=" * 80)

    sys.exit(0 if success else 1)
