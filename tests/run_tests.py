"""Run the whole unit-test suite:  python tests/run_tests.py   (stdlib only, no server needed)"""
import os
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
sys.path.insert(0, os.path.dirname(here))
suite = unittest.defaultTestLoader.discover(here, pattern="test_*.py", top_level_dir=here)
res = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
