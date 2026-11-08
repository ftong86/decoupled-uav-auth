#!/usr/bin/env python3
"""Run each Tamarin lemma independently and record the verifier's raw output."""
import argparse
from datetime import datetime
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
MODELS = (
    ("01", "01_normal_G.spthy", "Normal authentication"),
    ("02", "02_recovery_G.spthy", "Message loss recovery"),
    ("03", "03_dual_domain.spthy", "Dual domain execution"),
    ("04", "04_compromise.spthy", "Post-session compromise"),
    ("05", "05_state_handoff_G_bounded.spthy", "Bounded state handoff"),
)


def discover_lemmas(path):
    source = path.read_text(encoding="utf-8")
    names = re.findall(r"(?m)^\s*lemma\s+([A-Za-z][A-Za-z0-9_]*)\s*:", source)
    if not names or len(names) != len(set(names)):
        raise RuntimeError("Missing or duplicate lemma names in " + path.name)
    return names


def extract_result(output, lemma):
    pattern = re.compile(
        r"(?m)^[ \t]*" + re.escape(lemma)
        + r"[ \t]+\((exists-trace|all-traces)\):[ \t]*"
        + r"(verified|falsified|analysis incomplete)(?:[ \t]+\((\d+)\s+steps?\))?"
        + r"[^\r\n]*",
        re.IGNORECASE,
    )
    found = pattern.search(output)
    if not found:
        return None
    return {
        "raw_status": found.group(2).lower(),
        "native_line": found.group(0).strip(),
    }


def main():
    parser = argparse.ArgumentParser(description="Run Tamarin proofs for the five models")
    parser.add_argument("--model", choices=["all", "01", "02", "03", "04", "05"], default="all",
                        help="Select one model or all five (default: all)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Maximum seconds per lemma; this is a safety cutoff, not a benchmark")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--heap", default="2000M", help="GHC RTS maximum heap; e.g. 2000M")
    parser.add_argument("--dry-run", action="store_true",
                        help="List lemmas without running Tamarin")
    args = parser.parse_args()

    selected = [m for m in MODELS if args.model in ("all", m[0])]
    check = []
    for ident, filename, title in selected:
        path = HERE / filename
        if not path.is_file():
            parser.error("Missing model file: " + str(path))
        check.append((ident, path, title, discover_lemmas(path)))

    if args.dry_run:
        total = 0
        for ident, path, title, lemmas in check:
            print(f"\n{ident} {title} ({len(lemmas)} lemmas)")
            for lemma in lemmas:
                print("  " + lemma)
            total += len(lemmas)
        print(f"\nTotal: {total} lemmas")
        return 0

    if not shutil.which("tamarin-prover"):
        print("ERROR: tamarin-prover is not installed or is missing from PATH.", file=sys.stderr)
        print("Install Tamarin and Maude, then run the script again.", file=sys.stderr)
        return 127

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    results = HERE / "results" / run_id
    results.mkdir(parents=True)
    (HERE / "results" / "LATEST.txt").write_text(run_id + "\n", encoding="utf-8")

    print("Verifier:", shutil.which("tamarin-prover"))
    print("Evidence directory:", results, flush=True)

    verified = 0
    total = 0
    for ident, path, title, lemmas in check:
        logs_dir = results / ("model_" + ident)
        logs_dir.mkdir()
        native_lines = []
        model_verified = 0
        for number, lemma in enumerate(lemmas, 1):
            command = ["tamarin-prover", str(path), "--prove=" + lemma,
                       "+RTS", "-N" + str(args.threads), "-M" + args.heap, "-RTS"]
            print(f"[{ident} {number}/{len(lemmas)}] {lemma}", flush=True)
            try:
                proc = subprocess.run(command, cwd=HERE, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True,
                                      encoding="utf-8", errors="replace", timeout=args.timeout)
                output = proc.stdout or ""
                exitcode = proc.returncode
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                raw = exc.stdout or b""
                output = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                output += "\n[TIMEOUT: per-lemma cutoff reached]\n"
                exitcode = 124
                timed_out = True

            (logs_dir / (lemma + ".log")).write_text(
                "$ " + " ".join(command) + "\n\n" + output, encoding="utf-8")

            result = extract_result(output, lemma)
            if result and exitcode == 0:
                native_lines.append(result["native_line"])
                if result["raw_status"] == "verified":
                    model_verified += 1
            status = result["raw_status"] if result else ("timeout" if timed_out else "error")
            print("    " + (result["native_line"] if result else f"{status} (see log)"), flush=True)

        (logs_dir / "proof_lines.txt").write_text(
            "\n".join(native_lines) + "\n", encoding="utf-8")
        verified += model_verified
        total += len(lemmas)
        print(f"{ident} {title}: {model_verified}/{len(lemmas)} verified\n", flush=True)

    print("==============================================")
    print(f"TOTAL VERIFIED: {verified} / {total}")
    print("Verifier logs:", results)
    return 0 if verified == total else 1


if __name__ == "__main__":
    sys.exit(main())
