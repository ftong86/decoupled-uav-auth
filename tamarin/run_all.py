#!/usr/bin/env python3
# Run each proof independently, save original Tamarin output, and build
# screenshot-ready HTML summaries from actual verifier results.
import argparse
import csv
from datetime import datetime
from html import escape
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

STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: #1e1e1e;
       font-family: Consolas, 'DejaVu Sans Mono', Menlo, monospace; }
.page { max-width: 1100px; margin: 20px auto; padding: 16px 22px; }
h2 { font: 600 16px Arial, sans-serif; margin: 0 0 9px; }
.meta { font: 12px Arial, sans-serif; color: #666; margin: 0 0 12px; }
.proofs { width: 100%; border-collapse: collapse; table-layout: fixed;
          background: #f9f9fc; font-size: 13px; line-height: 1.7; }
.proofs td { padding: 0 7px; white-space: nowrap; overflow: hidden;
             text-overflow: ellipsis; vertical-align: top; }
.proofs td.name { width: 52%; color: #bd00b4; }
.proofs td.type { width: 23%; color: #333; text-align: right; }
.proofs td.result { width: 25%; }
.ok { color: #058325; font-weight: 700; }
.bad { color: #b22222; font-weight: 700; }
.na { color: #985c08; font-weight: 700; }
.steps { color: #333; font-weight: 400; }
.section { margin-bottom: 27px; page-break-inside: avoid; }
.note { font: 12px Arial, sans-serif; padding-top: 8px; color: #555; }
@media print {
  @page { size: A4; margin: 12mm; }
  .page { margin: 0; padding: 0; max-width: none; }
  .section { break-inside: avoid; }
}
"""

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
        "type": found.group(1),
        "raw_status": found.group(2).lower(),
        "steps": found.group(3) or "",
        "native_line": found.group(0).strip(),
    }

def proof_table(rows):
    trs = []
    for r in rows:
        status = r["status"]
        classname = "ok" if status == "verified" else ("bad" if status == "falsified" else "na")
        steps = " (" + r["steps"] + " steps)" if r["steps"] else ""
        proof_type = "(" + (r["type"] or "?") + "):"
        trs.append(
            '<tr><td class="name">' + escape(r["lemma"]) + '</td>'
            '<td class="type">' + escape(proof_type) + '</td>'
            '<td class="result"><span class="' + classname + '">'
            + escape(status) + '</span><span class="steps">'
            + escape(steps) + '</span></td></tr>'
        )
    return '<table class="proofs"><tbody>' + "\n".join(trs) + '</tbody></table>'

def page(title, sections, note):
    blocks = []
    for heading, rows in sections:
        blocks.append('<section class="section"><h2>' + escape(heading)
                      + '</h2>' + proof_table(rows) + '</section>')
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>' + escape(title) + '</title><style>' + STYLE
            + '</style></head><body><main class="page">'
            + "\n".join(blocks)
            + '<p class="note">' + escape(note) + '</p></main></body></html>')

def main():
    parser = argparse.ArgumentParser(description="Run Tamarin proofs and generate screenshot-ready summaries")
    parser.add_argument("--model", choices=["all", "01", "02", "03", "04", "05"], default="all",
                        help="Select one model or all five (default: all)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Maximum seconds per lemma; this is a safety cutoff, not a benchmark")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--heap", default="2000M", help="GHC RTS maximum heap; e.g. 2000M")
    parser.add_argument("--dry-run", action="store_true", help="List lemmas without running Tamarin")
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

    all_rows = []
    sections = []
    print("Evidence directory:", results)
    print("Verifier: ", shutil.which("tamarin-prover"))
    print("Only Tamarin's actual result lines count as VERIFIED.\n", flush=True)

    for ident, path, title, lemmas in check:
        logs_dir = results / ("model_" + ident)
        logs_dir.mkdir()
        rows = []
        native_lines = []
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
                "$ " + " ".join(command) + "\n\n" + output,
                encoding="utf-8",
            )
            result = extract_result(output, lemma)
            status = (result["raw_status"] if result is not None and exitcode == 0
                      else ("timeout" if timed_out else "error"))
            if status not in ("verified", "falsified", "analysis incomplete"):
                if not timed_out:
                    status = "error" if exitcode != 0 else "unresolved"
            row = {
                "model": ident, "lemma": lemma, "type": result["type"] if result else "",
                "status": status, "steps": result["steps"] if result else "",
                "exit_code": exitcode, "log": "model_" + ident + "/" + lemma + ".log"
            }
            rows.append(row)
            all_rows.append(row)
            if result and exitcode == 0:
                native_lines.append(result["native_line"])
            print("    " + (result["native_line"] if result else f"{status} (see log)"), flush=True)

        (logs_dir / "proof_lines.txt").write_text(
            "\n".join(native_lines) + "\n", encoding="utf-8")
        verified = sum(r["status"] == "verified" for r in rows)
        heading = f"({ident}) {title} — {verified}/{len(rows)} verified"
        (results / (ident + "_screenshot.html")).write_text(
            page(heading, [(heading, rows)],
                 "Generated from recorded Tamarin output. Red/orange entries are not verified."),
            encoding="utf-8")
        sections.append((heading, rows))
        print(f"{ident}: {verified}/{len(rows)} verified\n", flush=True)

    with (results / "results.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    total_verified = sum(r["status"] == "verified" for r in all_rows)
    total = len(all_rows)
    (results / "verification_summary.txt").write_text(
        "\n".join(
            [f"{ident} {title}: {sum(r['status']=='verified' for r in all_rows if r['model']==ident)}/{len(lemmas)} verified"
             for ident, _, title, lemmas in check]
            + ["", f"TOTAL VERIFIED: {total_verified} / {total}", "",
               "Proof lines and logs come directly from Tamarin. No statuses are fabricated.",
               "Only the selected models are included in this run."]
        ) + "\n", encoding="utf-8")
    (results / "all_models_screenshot.html").write_text(
        page("Tamarin proof results", sections,
             f"Actual verification result: {total_verified}/{total}. Models may use different abstraction levels."),
        encoding="utf-8")
    print("\n==============================================")
    print(f"TOTAL VERIFIED: {total_verified} / {total}")
    print("Summary:", results / "verification_summary.txt")
    print("Five screenshot pages:", results / "0X_screenshot.html")
    print("Combined screenshot:", results / "all_models_screenshot.html")
    print("Original logs:", results / "model_XX" / "<lemma>.log")
    if total_verified != total:
        print("Some proofs did not verify. Inspect the original logs before reporting results.")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
