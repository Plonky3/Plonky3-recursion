import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_SCRIPT = REPO_ROOT / "scripts" / "benchmark.sh"


class BenchmarkScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)
        self.counter_path = self.temp_path / "cargo-invocations"
        cargo = self.temp_path / "cargo"
        cargo.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                from pathlib import Path
                import sys

                counter_path = Path(os.environ["BENCHMARK_TEST_COUNTER"])
                invocation = int(counter_path.read_text()) + 1 if counter_path.exists() else 1
                counter_path.write_text(str(invocation))

                args = " ".join(sys.argv[1:])
                if "recursive_aggregation" in args:
                    mode = "aggregation"
                elif "recursive_fibonacci" in args:
                    mode = "fibonacci"
                elif "recursive_keccak" in args:
                    mode = "keccak"
                else:
                    print(f"unexpected cargo arguments: {args}", file=sys.stderr)
                    sys.exit(91)

                scenario = os.environ["BENCHMARK_TEST_SCENARIO"]
                if scenario == "failure" or (
                    scenario == "failure_after_success" and invocation == 2
                ):
                    if mode == "aggregation":
                        print("Aggregation level 1:")
                        print("INFO [ 125 ms] prove_aggregation_layer")
                    else:
                        print("INFO [ 0.125 s] prove_next_layer")
                    print("stub cargo failed", file=sys.stderr)
                    sys.exit(7)

                if mode == "aggregation":
                    if invocation == 1:
                        print("Aggregation level 1:")
                        print("INFO [ 10 ms] prove_aggregation_layer")
                        print("INFO [ 14 ms] prove_aggregation_layer")
                        print("Aggregation level 2:")
                        print("INFO [ 20 ms] prove_aggregation_layer")
                    else:
                        print("Aggregation level 1:")
                        print("INFO [ 30 ms] prove_aggregation_layer")
                        print("INFO [ 18 ms] prove_aggregation_layer")
                        print("Aggregation level 2:")
                        print("INFO [ 40 ms] prove_aggregation_layer")
                elif invocation == 1:
                    print("INFO [ 10 ms] prove_next_layer")
                    print("INFO [ 1.5 s] prove_next_layer")
                else:
                    print("INFO [ 30 ms] prove_next_layer")
                    print("INFO [ 2.5 s] prove_next_layer")
                """
            )
        )
        cargo.chmod(0o755)

    def run_benchmark(self, mode, runs, scenario="success"):
        self.counter_path.unlink(missing_ok=True)
        env = os.environ.copy()
        env["PATH"] = f"{self.temp_path}{os.pathsep}{env['PATH']}"
        env["BENCHMARK_TEST_COUNTER"] = str(self.counter_path)
        env["BENCHMARK_TEST_SCENARIO"] = scenario
        result = subprocess.run(
            ["bash", str(BENCHMARK_SCRIPT), mode, str(runs)],
            env=env,
            capture_output=True,
            text=True,
        )
        count = int(self.counter_path.read_text()) if self.counter_path.exists() else 0
        return result, count

    def parse_csv_rows(self, stdout):
        rows = {}
        for line in stdout.splitlines():
            columns = [column.strip() for column in line.split(",")]
            if len(columns) != 5 or not columns[0].isdigit():
                continue
            rows[int(columns[0])] = [
                int(column.removesuffix(" ms")) for column in columns[1:]
            ]
        return rows

    def test_cargo_failure_is_propagated_and_stops_all_modes(self):
        for mode in ("fibonacci", "keccak", "aggregation"):
            with self.subTest(mode=mode):
                failed, invocation_count = self.run_benchmark(mode, 2, "failure")

                self.assertEqual(failed.returncode, 7)
                self.assertEqual(invocation_count, 1)
                self.assertIn("stub cargo failed", failed.stderr)

    def test_later_cargo_failure_is_propagated_and_stops_remaining_runs(self):
        failed, invocation_count = self.run_benchmark(
            "aggregation", 3, "failure_after_success"
        )

        self.assertEqual(failed.returncode, 7)
        self.assertEqual(invocation_count, 2)
        self.assertIn("stub cargo failed", failed.stderr)

    def test_fibonacci_and_keccak_report_cross_run_statistics_in_milliseconds(self):
        expected = {
            1: [10, 20, 20, 30],
            2: [1500, 2000, 2000, 2500],
        }
        for mode in ("fibonacci", "keccak"):
            with self.subTest(mode=mode):
                completed, invocation_count = self.run_benchmark(mode, 2)

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(invocation_count, 2)
                self.assertEqual(self.parse_csv_rows(completed.stdout), expected)

    def test_aggregation_retains_singletons_after_skipping_repeated_first_samples(self):
        completed, invocation_count = self.run_benchmark("aggregation", 2)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(invocation_count, 2)
        self.assertEqual(
            self.parse_csv_rows(completed.stdout),
            {
                1: [14, 16, 16, 18],
                2: [20, 30, 30, 40],
            },
        )

    def test_single_aggregation_run_uses_every_sample(self):
        completed, invocation_count = self.run_benchmark("aggregation", 1)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(invocation_count, 1)
        self.assertEqual(
            self.parse_csv_rows(completed.stdout),
            {
                1: [12, 12, 12, 12],
                2: [20, 20, 20, 20],
            },
        )


if __name__ == "__main__":
    unittest.main()
