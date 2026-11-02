# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Checks throughput aggregation semantics; no machine-specific timing thresholds."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("local_tps", Path(__file__).with_name("local-tps.py"))
TPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TPS)


class SummaryTests(unittest.TestCase):
    def test_sustained_uses_total_count_and_elapsed_not_average_instantaneous_tps(self):
        rows = [{"transactions": "100", "count": "100", "elapsed_ns": str(ns)}
                for ns in (1_000_000_000, 3_000_000_000)]
        result = TPS.summarize(rows)
        self.assertEqual(result["transactions"], 200)
        self.assertEqual(result["sustained_tps"], 50)
        self.assertEqual(result["block_latency_ms"]["p95"], 3000)

    def test_stage_values_and_quantiles_have_explicit_units(self):
        rows = [{"transactions": "2", "count": "2", "elapsed_ns": str(ns),
                 "admission_ns": "1000000", "production_ns": "2000000", "publication_ns": "3000000"}
                for ns in (10_000_000, 20_000_000, 30_000_000)]
        result = TPS.summarize(rows)
        self.assertEqual(result["block_latency_ms"]["p50"], 20)
        self.assertEqual(result["median_stage_ms"], {"admission": 1, "production": 2, "publication": 3})


if __name__ == "__main__":
    unittest.main()
