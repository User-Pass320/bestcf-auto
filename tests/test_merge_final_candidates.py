import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "merge-final-candidates.py"
SPEC = importlib.util.spec_from_file_location("merge_final_candidates", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
merge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = merge
SPEC.loader.exec_module(merge)


class MergeFinalCandidatesTests(unittest.TestCase):
    def test_primary_order_is_preserved_and_supplement_fills_unique_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "primary.txt"
            supplement = root / "supplement.txt"
            output = root / "merged.txt"
            primary.write_text(
                "1.1.1.1:443#日本-1\n2.2.2.2:443#新加坡-1\n",
                encoding="utf-8",
            )
            supplement.write_text(
                "2.2.2.2:443#新加坡-9\n3.3.3.3:8443#美国-1\ninvalid\n",
                encoding="utf-8",
            )

            summary = merge.merge_candidate_files(primary, [supplement], output)

            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                ["1.1.1.1:443#日本-1", "2.2.2.2:443#新加坡-1", "3.3.3.3:8443#美国-1"],
            )
            self.assertEqual(summary["primary_candidate_count"], 2)
            self.assertEqual(summary["supplement_added_count"], 1)
            self.assertEqual(summary["duplicate_count"], 1)
            self.assertEqual(summary["supplements"][0]["invalid_count"], 1)

    def test_missing_supplement_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "primary.txt"
            output = root / "merged.txt"
            primary.write_text("1.1.1.1:443#日本-1\n", encoding="utf-8")

            summary = merge.merge_candidate_files(primary, [root / "missing.txt"], output)

            self.assertEqual(summary["output_count"], 1)
            self.assertFalse(summary["supplements"][0]["exists"])


if __name__ == "__main__":
    unittest.main()
