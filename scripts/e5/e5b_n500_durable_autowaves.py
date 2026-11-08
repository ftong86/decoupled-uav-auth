#!/usr/bin/env python3
"""E5-B 4-seed durable worker (not a mid-seed checkpoint implementation).

- Original E5 V2 simulator binary, scene generation and analyzer remain unchanged.
- Two independent seeds run together; next wave begins automatically after validation.
- Survives instance reboot via an enabled persistent systemd service.
- A completed valid seed is never repeated; an interrupted incomplete seed reruns
  from time 0, since no scientifically validated in-process checkpoint exists.
- Scope of optional old-data removal is exactly the abandoned 20261014 batch.
"""
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASE = Path("/data/e5b")
RUNS = BASE / "runs"
SOURCE = BASE / "incoming/e5b_n500_formal4.py/e5b_n500_formal4_fixed.py"
SOURCE_SHA = "f554b469b18e1e953bcee63e636aa9d5b1aec87e52ba98959b54ef5078a385df"
BATCH_NAME = "E5B_N500_PONLY_FORMAL_S01_04_DURABLE_20261015"
OLD_BATCH = "E5B_N500_PONLY_FORMAL_S01_04_20261014"
UNIT = "e5b-n500-durable-20261015.service"
SEEDS = ((1, 2), (3, 4))
RUN_LIMIT = "48h"


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, obj):
    path = Path(path)
    tmp = path.with_name(path.name + ".writing")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def state(batch, result, **details):
    write_json(batch / "STATE.json", {
        "result": result, "updated_utc": stamp(),
        "mid_seed_checkpoint_verified": False,
        **details,
    })


def fixed_module():
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise RuntimeError("SOURCE_MISSING_OR_SYMLINK")
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if digest != SOURCE_SHA:
        raise RuntimeError("SOURCE_SHA256_MISMATCH")
    spec = importlib.util.spec_from_file_location("e5b_frozen_orchestrator", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.BATCH_NAME = BATCH_NAME
    module.UNIT_NAME = UNIT.removesuffix(".service")
    return module


def disk_ready():
    result = subprocess.run(["mountpoint", "-q", "/data"], check=False)
    if result.returncode:
        raise RuntimeError("DATA_DISK_NOT_MOUNTED")
    if shutil.disk_usage(BASE).free < 90 * (1024 ** 3):
        raise RuntimeError("LESS_THAN_90GiB_FREE")


def no_active_simulation(job):
    target = f"--config={job / 'scene.cloud.json'}".encode()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmd = (proc / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        if target in cmd:
            raise RuntimeError(f"ACTIVE_SIMULATOR_ALREADY_EXISTS: {proc.name}")


def verify_registration(batch):
    p = read_json(batch / "REGISTERED_PLAN.json")
    if p.get("rng_seeds") != [1, 2, 3, 4] or p.get("rng_run") != 1:
        raise RuntimeError("REGISTERED_PLAN_NOT_4_SEEDS")
    if p.get("n_uav") != 500 or not p.get("formal"):
        raise RuntimeError("REGISTERED_PLAN_WRONG_SCOPE")
    actual = hashlib.sha256((batch / "REGISTERED_PLAN.json").read_bytes()).hexdigest()
    expected = (batch / "PLAN.sha256").read_text().split()[0]
    if actual != expected:
        raise RuntimeError("REGISTERED_PLAN_HASH_CHANGED")


def valid_completed(job):
    if not (job / "ANALYSIS_OK").is_file():
        return False
    record = read_json(job / "P/run_record.json")
    data = read_json(job / "FORMAL_ANALYSIS.json")
    scores = data.get("per_scheme", [])
    return (record.get("exit_code") == 0 and len(scores) == 1
            and scores[0].get("mode") == "P" and scores[0].get("n") == 500
            and scores[0].get("measurement_valid") is True)


def is_ready_for_analysis(job):
    if not (job / "status").is_file():
        return False
    return ("RESULT=EXIT0_PENDING_VALIDATION"
            in (job / "status").read_text(encoding="utf-8")
            and (job / "P/run_record.json").is_file())


def reset_incomplete(job, batch):
    """Drop only an unvalidated, interrupted attempt in the newly registered batch."""
    if job.parent != batch or not re.fullmatch(r"n500_seed00[1-4]_run001", job.name):
        raise RuntimeError("REFUSE_UNEXPECTED_JOB_PATH")
    if job.is_symlink() or not job.is_dir() or (job / "ANALYSIS_OK").exists():
        raise RuntimeError("REFUSE_RESET_VALIDATED_OR_SYMLINK")
    no_active_simulation(job)
    inputs = read_json(job / "REGISTERED_INPUT_SHA256.json")
    scene = job / "scene.cloud.json"
    if hashlib.sha256(scene.read_bytes()).hexdigest() != inputs.get("scene_cloud"):
        raise RuntimeError("SCENE_SHA_CHANGED")
    if job.joinpath("P").is_symlink():
        raise RuntimeError("OUTPUT_ROOT_SYMLINK")
    journal = batch / "ATTEMPT_EVENTS.jsonl"
    with journal.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "utc": stamp(), "job": job.name,
            "event": "DISCARD_INCOMPLETE_OUTPUT_AND_RERUN_FROM_ZERO",
            "checkpoint_available": False,
        }, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    for name in ("sim", "auth", "state"):
        p = job / "P" / name
        if p.is_symlink():
            raise RuntimeError("REFUSE_OUTPUT_SYMLINK")
        if p.exists():
            shutil.rmtree(p)
        p.mkdir()
    for p in (job / "status", job / "run.log", job / "resources.txt",
              job / "command.txt", job / "P/run_record.json",
              job / "FORMAL_ANALYSIS.json"):
        if p.is_symlink():
            raise RuntimeError("REFUSE_FILE_SYMLINK")
        p.unlink(missing_ok=True)


def run_one(mod, batch, seed):
    job = mod.job_path(batch, seed)
    if valid_completed(job):
        return "ALREADY_VALID"
    if is_ready_for_analysis(job):
        return "EXIT0_NEEDS_ANALYSIS"
    if (job / "status").exists() or (job / "run.log").exists():
        reset_incomplete(job, batch)
    # mod.single_run is the already sandbox-tested exact simulator invocation.
    code = mod.single_run(BASE, batch, seed, time_limit=RUN_LIMIT)
    if code != 0:
        raise RuntimeError(f"SEED_{seed}_EXIT_{code}")
    return "EXIT0_NEEDS_ANALYSIS"


def work():
    disk_ready()
    mod = fixed_module()
    batch = RUNS / BATCH_NAME
    verify_registration(batch)
    for wave_index, pair in enumerate(SEEDS, 1):
        pending = [seed for seed in pair
                   if not valid_completed(mod.job_path(batch, seed))]
        if pending:
            state(batch, f"WAVE_{wave_index}_RUNNING", seeds=list(pair))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = {s: pool.submit(run_one, mod, batch, s)
                           for s in pending}
                errors = []
                for s, result in futures.items():
                    try:
                        result.result()
                    except Exception as exc:
                        errors.append(f"seed{s}: {exc}")
                if errors:
                    state(batch, "HALTED_NEEDS_ATTENTION", errors=errors)
                    return 0  # prevent endless systemd restart and billing
        state(batch, f"WAVE_{wave_index}_ANALYZING")
        for seed in pair:
            job = mod.job_path(batch, seed)
            if not valid_completed(job):
                try:
                    mod.analyze_run(BASE, batch, seed)
                except Exception as exc:
                    state(batch, "HALTED_NEEDS_ATTENTION",
                          error=f"seed{seed} ANALYSIS: {exc}")
                    return 0
        state(batch, f"WAVE_{wave_index}_VALIDATED")
    state(batch, "FOUR_FORMAL_RUNS_VALIDATED",
          note="Original outputs must still be copied to Windows D: and SHA256 checked")
    return 0


def cleanup_abandoned():
    """Explicitly user-authorized removal of the old, incomplete 20261014 batch only."""
    old = RUNS / OLD_BATCH
    if not old.exists():
        return
    if old.is_symlink() or old.resolve().parent != RUNS.resolve():
        raise RuntimeError("REFUSE_DELETE_OUTSIDE_RUNS")
    if not (RUNS / BATCH_NAME / "REGISTERED_PLAN.json").is_file():
        raise RuntimeError("NEW_BATCH_MUST_BE_REGISTERED_FIRST")
    ostate = read_json(old / "STATE.json")
    if ostate.get("result") != "WAVE_1_RUNNING":
        raise RuntimeError("REFUSE_OLD_BATCH_UNEXPECTED_STATE")
    old_plan = read_json(old / "REGISTERED_PLAN.json")
    if old_plan.get("rng_seeds") != [1, 2, 3, 4] or old_plan.get("n_uav") != 500:
        raise RuntimeError("REFUSE_OLD_BATCH_WRONG_SCOPE")
    for seed in (1, 2, 3, 4):
        job = old / f"n500_seed{seed:03d}_run001"
        if (job / "ANALYSIS_OK").exists() or (job / "FORMAL_ANALYSIS.json").exists():
            raise RuntimeError("REFUSE_DELETE_OLD_POSSIBLE_VALID_DATA")
        no_active_simulation(job)
        status = job / "status"
        if status.is_file() and "RESULT=RUNNING" not in status.read_text():
            raise RuntimeError("REFUSE_DELETE_COMPLETED_RUN")
    shutil.rmtree(old)
    print("REMOVED_ONLY_ABANDONED_20261014_BATCH", flush=True)


def install():
    if os.geteuid() != 0:
        raise RuntimeError("ROOT_REQUIRED")
    disk_ready()
    # Reject parallel formal batches that would silently double ECS cost.
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            cmd = (proc / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        if (b"--config=/data/e5b/runs/" in cmd
                and b"n500_seed" in cmd
                and BATCH_NAME.encode() not in cmd):
            raise RuntimeError("ANOTHER_N500_BATCH_IS_RUNNING")
    mod = fixed_module()
    batch = RUNS / BATCH_NAME
    if batch.exists():
        verify_registration(batch)
    else:
        created = mod.make_batch()
        if created != batch:
            raise RuntimeError("WRONG_BATCH_REGISTRATION_PATH")
    installed_copy = batch / "durable_controller.py"
    source = Path(__file__).resolve()
    if installed_copy.exists():
        if installed_copy.read_bytes() != source.read_bytes():
            raise RuntimeError("INSTALLED_CONTROLLER_DIFFERS; REFUSE_OVERWRITE")
    else:
        shutil.copyfile(source, installed_copy)
    unitfile = Path("/etc/systemd/system") / UNIT
    content = f"""[Unit]
Description=E5-B N500 four-seed durable batch
After=local-fs.target
RequiresMountsFor=/data
StartLimitIntervalSec=600
StartLimitBurst=3

[Service]
Type=simple
WorkingDirectory={BASE / 'build/IoD_Sim/ns3'}
ExecStart=/usr/bin/python3 {installed_copy} worker
Restart=on-failure
RestartSec=30s
KillMode=control-group
MemoryMax=29G
Environment=PYTHONUNBUFFERED=1
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
"""
    if unitfile.exists():
        if unitfile.read_text() != content:
            raise RuntimeError("SYSTEMD_UNIT_CONFLICT")
    else:
        unitfile.write_text(content, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", UNIT], check=True)
    # Deliberately keep the aborted old batch unless an explicit cleanup flag
    # is passed; no retention of this data is required for new calculations.
    print(f"AUTO_SERVICE_ENABLED={UNIT}")
    print(f"BATCH={batch}")
    print("AFTER_REBOOT=RECOVERS_COMPLETED_SEEDS_AND_RERUNS_INCOMPLETE_FROM_ZERO")
    print("MID_SEED_CHECKPOINT=NOT_VERIFIED_NOT_SUPPORTED")
    # The user has explicitly waived retention of the *old interrupted batch*.
    # Its deletion is narrow and refuses anything that appears validated.
    try:
        cleanup_abandoned()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"WARNING_OLD_INTERRUPTED_BATCH_NOT_DELETED: {exc}")


def main():
    if len(sys.argv) < 2:
        raise ValueError("Usage: script.py install|worker|status|purge-old")
    command = sys.argv[1]
    if command == "install":
        install()
    elif command == "worker":
        return work()
    elif command == "status":
        print(json.dumps(read_json(RUNS / BATCH_NAME / "STATE.json"),
                         indent=2, ensure_ascii=False))
    elif command == "purge-old":
        cleanup_abandoned()
    else:
        raise ValueError("Unknown command: " + command)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        sys.exit(1)
