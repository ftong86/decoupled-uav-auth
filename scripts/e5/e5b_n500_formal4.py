#!/usr/bin/env python3
# E5-B ECS N=500 P-only: four independently registered formal seeds in two waves.
# Existing ns-3 binaries and the already-verified development scene are INPUTS ONLY.
# All per-seed formal outputs are new; no modification/deletion of prior inputs.
# Required: Python 3.10+, root access for systemd-run, /data mounted.
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
from datetime import datetime, timezone

BASE = Path("/data/e5b")
BATCH_NAME = "E5B_N500_PONLY_FORMAL_S01_04_20261014"
DEV_NAME = "n500_s033_r003_dev_only_20261013"
ANALYZER_REL = "build/handoff_source_20261013/CLOUD_E5B_SOURCE_HANDOFF/tools_batch1_n25_n100/tools/formal_analyze.py"
UNIT_NAME = "e5b-n500-formal-s01-04-20261014"
SEEDS = (1, 2, 3, 4)
BLOCKERS = {
    "UE_ENB_RRC_EVIDENCE_MISMATCH",
    "LTE_UNEXPECTED_TARGET_PATH",
    "MISSING_EVIDENCE",
    "SIMULATION_FAILED",
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(p):
    return sha(p.read_bytes())


def read_json(p):
    obj = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"Expected JSON object: {p}")
    return obj


def save_json(p, obj):
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                 encoding="utf-8")


def assert_ready(base, check_mount=True, min_free=90 * (1024 ** 3)):
    if check_mount:
        subprocess.run(["mountpoint", "-q", "/data"], check=True)
    if shutil.disk_usage(base).free < min_free:
        raise RuntimeError("Insufficient free space on /data (require >=90 GiB)")
    dev = base / "runs" / DEV_NAME
    ns3 = base / "build/IoD_Sim/ns3"
    analyzer = base / ANALYZER_REL
    for p in (
        dev / "frozen/scene.json",
        dev / "frozen/manifest.json",
        dev / "scene.cloud.json",
        dev / "path_mapping.json",
        dev / "inputs.sha256",
        dev / "status",
        ns3 / "ns3",
        ns3 / "build/ns3.45-scenario-debug",
        analyzer,
        Path("/usr/bin/time"),
        Path("/usr/bin/timeout"),
    ):
        if not p.is_file():
            raise FileNotFoundError(f"Missing required file: {p}")
    if not os.access(ns3 / "ns3", os.X_OK):
        raise RuntimeError("The frozen ns3 launcher is not executable")
    if "EXIT_CODE=0" not in (dev / "status").read_text():
        raise RuntimeError("The prior N500 development run did not exit 0")
    # Enforce the existing SHA checks before any formal registration/compute.
    result = subprocess.run(
        ["sha256sum", "-c", str(dev / "inputs.sha256")],
        cwd=dev, capture_output=True, text=True,
    )
    if result.returncode:
        raise RuntimeError("Frozen input checksum failed:\n" + result.stdout[-1200:]
                           + result.stderr[-1200:])
    return dev, ns3, analyzer


def translate(value, old_root, new_root, counts):
    if isinstance(value, dict):
        return {k: translate(v, old_root, new_root, counts)
                for k, v in value.items()}
    if isinstance(value, list):
        return [translate(v, old_root, new_root, counts) for v in value]
    if isinstance(value, str) and value.startswith(old_root + "/"):
        suffix = value[len(old_root) + 1:]
        bits = suffix.split("/")
        if (len(bits) < 1 or bits[0] not in ("sim", "auth", "state")
                or any(part in ("", ".", "..") for part in bits)
                or "\\" in suffix):
            raise ValueError("Unsafe output path under scene template: " + value)
        counts[bits[0]] += 1
        return new_root + "/" + suffix
    return value


def check_template(dev):
    original_bytes = (dev / "frozen/scene.json").read_bytes()
    original = json.loads(original_bytes)
    cloud = read_json(dev / "scene.cloud.json")
    manifest = read_json(dev / "frozen/manifest.json")
    mapping = read_json(dev / "path_mapping.json")
    expected = {
        "kind": "E5_V2_DEVELOPMENT_ONLY",
        "formal": False,
        "n_uav": 500,
        "cluster_count": 20,
        "enb_count": 60,
        "effective_uav_per_cluster": 25,
        "simulation_duration_sec": 90.0,
        "rng_seed": 33,
        "rng_run": 3,
        "background_traffic": False,
        "layout": "scaled",
        "variant": ["P"],
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f"Unexpected DEV manifest {key}: {manifest.get(key)!r}")
    if not isinstance(original, dict) or len(original.get("drones", [])) != 500:
        raise ValueError("Expected a 500-UAV frozen original scene")
    if mapping.get("inverse_mapping_identical") is not True:
        raise ValueError("The original path remapping is not verified")
    if file_hash(dev / "frozen/scene.json") != mapping.get("original_scene_sha256"):
        raise ValueError("Frozen scene SHA256 mismatch")
    if file_hash(dev / "scene.cloud.json") != mapping.get("cloud_scene_sha256"):
        raise ValueError("Deployed scene SHA256 mismatch")
    old_root = str(dev / "P")
    if mapping.get("new_root") != old_root:
        raise ValueError("Unexpected development root in original mapping")
    counts = {"sim": 0, "auth": 0, "state": 0}
    recovered = translate(cloud, old_root, mapping["old_root"], counts)
    if recovered != original or not all(counts.values()):
        raise ValueError("DEV scene is NOT identical to frozen scene except output paths")
    return cloud, manifest, sha(original_bytes), sha((dev / "frozen/manifest.json").read_bytes())


def job_path(batch, seed):
    return batch / f"n500_seed{seed:03d}_run001"


def make_batch(base=BASE, check_mount=True, min_free=90 * (1024 ** 3)):
    dev, ns3, analyzer = assert_ready(base, check_mount, min_free)
    cloud, src_manifest, src_scene_sha, src_manifest_sha = check_template(dev)
    batch = base / "runs" / BATCH_NAME
    if batch.exists():
        raise FileExistsError(f"STOP: batch already exists; never overwrite: {batch}")

    # Real pre-registration timestamp occurs BEFORE any command can start.
    registration_time = now()
    binary_hash = file_hash(ns3 / "build/ns3.45-scenario-debug")
    launcher_hash = file_hash(ns3 / "ns3")
    plan = {
        "kind": "E5_B_N500_FORMAL_P_ONLY_REGISTERED_20261014",
        "formal": True,
        "registered_utc": registration_time,
        "registration_before_any_simulator_run": True,
        "approved_on": "2026-10-14",
        "approval_scope": "N500 P-only; four independent seeds, two waves of two",
        "n_uav": 500,
        "enb_count": 60,
        "simulation_duration_sec": 90.0,
        "rng_seeds": list(SEEDS),
        "rng_run": 1,
        "wave_schedule": [[1, 2], [3, 4]],
        "dev_seed33_run3_excluded": True,
        "original_frozen_scene_sha256": src_scene_sha,
        "original_generator_manifest_sha256": src_manifest_sha,
        "frozen_ns3_launcher_sha256": launcher_hash,
        "frozen_scenario_binary_sha256": binary_hash,
        "source_of_template": str(dev / "frozen/scene.json"),
        "template_origin_kind": "E5_V2_DEVELOPMENT_ONLY",
        "source_analyzer": str(analyzer),
        "frozen_analyzer_sha256": file_hash(analyzer),
        "measurement_validation": "pending",
    }

    batch.mkdir(mode=0o750)
    save_json(batch / "REGISTERED_PLAN.json", plan)
    (batch / "PLAN.sha256").write_text(
        file_hash(batch / "REGISTERED_PLAN.json") +
        "  REGISTERED_PLAN.json\n", encoding="ascii"
    )
    shutil.copyfile(dev / "frozen/scene.json", batch / "ORIGINAL_FROZEN_SCENE.json")
    shutil.copyfile(dev / "frozen/manifest.json", batch / "ORIGINAL_DEV_MANIFEST.json")
    shutil.copyfile(dev / "path_mapping.json", batch / "ORIGINAL_PATH_MAPPING.json")
    for seed in SEEDS:
        job = job_path(batch, seed)
        job.mkdir()
        for part in ("sim", "auth", "state"):
            (job / "P" / part).mkdir(parents=True, exist_ok=False)

        counts = {"sim": 0, "auth": 0, "state": 0}
        remapped = translate(cloud, str(dev / "P"), str(job / "P"), counts)
        if not all(counts.values()):
            raise ValueError(f"Missing output category in remapping for seed {seed}")
        original_again = translate(
            remapped, str(job / "P"), str(dev / "P"),
            {"sim": 0, "auth": 0, "state": 0}
        )
        if original_again != cloud:
            raise ValueError("Forbidden scene change beyond output paths")

        save_json(job / "scene.cloud.json", remapped)
        # Also retain the exact per-seed scenario in the conventional formal P/ tree.
        shutil.copyfile(job / "scene.cloud.json", job / "P/scene.json")
        meta = dict(src_manifest)
        meta.update({
            "kind": "E5_B_FORMAL_P_ONLY_V1",
            "formal": True,
            "status": "PRE_REGISTERED_NOT_RUN",
            "rng_seed": seed,
            "rng_run": 1,
            "registration_utc": registration_time,
            "registration_before_any_simulator_run": True,
            "generator_origin_manifest_sha256": src_manifest_sha,
            "original_frozen_scene_sha256": src_scene_sha,
            "pre_registered_modes": ["P"],
            "formal_plan_sha256": file_hash(batch / "REGISTERED_PLAN.json"),
            "dev_template_reused_for_scene_structure": True,
        })
        save_json(job / "manifest.json", meta)
        save_json(job / "P/manifest.json", meta)
        save_json(job / "REGISTERED_INPUT_SHA256.json", {
            "scene_cloud": file_hash(job / "scene.cloud.json"),
            "manifest": file_hash(job / "manifest.json"),
            "scenario_binary": binary_hash,
            "ns3_launcher": launcher_hash,
            "original_scene": src_scene_sha,
        })
        save_json(job / "OUTPUT_PATH_REMAP.json", {
            "dev_source": str(dev / "P"),
            "formal_target": str(job / "P"),
            "counts": counts,
            "reverse_mapping_identical": True,
        })
    # Freeze the controlling script inside the newly registered batch.
    shutil.copyfile(Path(__file__), batch / "orchestrator.py")
    save_json(batch / "STATE.json", {
        "result": "REGISTERED_NOT_STARTED",
        "updated_utc": now(),
    })
    return batch


def elapsed_seconds(resource):
    if not resource.is_file():
        return None
    text = resource.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Elapsed \(wall clock\) time.*:\s*(\S+)", text)
    if not match:
        return None
    bits = match.group(1).split(":")
    try:
        if len(bits) == 3:
            return int(bits[0]) * 3600 + int(bits[1]) * 60 + float(bits[2])
        if len(bits) == 2:
            return int(bits[0]) * 60 + float(bits[1])
    except ValueError:
        pass
    return None


def write_batch_state(batch, result, **info):
    save_json(batch / "STATE.json", {
        "result": result, "updated_utc": now(), **info,
    })


def single_run(base, batch, seed, time_limit="48h"):
    ns3 = base / "build/IoD_Sim/ns3"
    job = job_path(batch, seed)
    status = job / "status"
    # Refuse a changed input before creating any RUNNING status.
    recorded = read_json(job / "REGISTERED_INPUT_SHA256.json")
    if (file_hash(job / "scene.cloud.json") != recorded["scene_cloud"]
            or file_hash(job / "manifest.json") != recorded["manifest"]
            or file_hash(ns3 / "build/ns3.45-scenario-debug")
            != recorded["scenario_binary"]):
        raise RuntimeError(f"Frozen inputs changed before seed {seed}")
    # Atomic creation ensures even a repeated worker cannot rerun/overwrite a seed.
    with status.open("x", encoding="utf-8") as f:
        f.write("RESULT=RUNNING\nSTARTED_UTC=" + now() + "\n")
    start = now()
    args = [
        "/usr/bin/time", "-v", "-o", str(job / "resources.txt"),
        "timeout", "--signal=TERM", "--kill-after=60s", time_limit,
        "./ns3", "run",
        f"scenario --config={job / 'scene.cloud.json'} --RngSeed={seed} --RngRun=1",
        "--no-build",
    ]
    (job / "command.txt").write_text(
        "cwd=" + str(ns3) + "\n" + " ".join(args) + "\n",
        encoding="utf-8"
    )
    exit_code = -1
    failure = None
    try:
        with (job / "run.log").open("x", encoding="utf-8") as output:
            exit_code = subprocess.run(
                args, cwd=ns3, stdout=output,
                stderr=subprocess.STDOUT, check=False,
            ).returncode
    except Exception as exc:
        failure = str(exc)
    end = now()
    record = {
        "seed": seed,
        "rng_seed": seed,
        "rng_run": 1,
        "mode": "P",
        "exit_code": exit_code,
        "simulator_exit": exit_code,
        "wall_seconds": elapsed_seconds(job / "resources.txt"),
        "timed_out": exit_code in (124, 137),
        "status": "SUCCESS" if exit_code == 0 else "FAILED",
        "command": "cwd=" + str(ns3) + "\n" + " ".join(args),
        "started_utc": start,
        "finished_utc": end,
        "failure": failure,
    }
    save_json(job / "P/run_record.json", record)
    if exit_code == 0:
        result = "EXIT0_PENDING_VALIDATION"
    elif exit_code in (124, 137):
        result = "TIMEOUT_OR_KILLED"
    else:
        result = "FAILED"
    status.write_text(
        f"RESULT={result}\nEXIT_CODE={exit_code}\nFINISHED_UTC={end}\n",
        encoding="utf-8"
    )
    return exit_code


def analyze_run(base, batch, seed, analyzer_override=None):
    job = job_path(batch, seed)
    status = (job / "status").read_text()
    if "RESULT=EXIT0_PENDING_VALIDATION" not in status:
        raise RuntimeError(f"Seed {seed} not exited cleanly")
    log = (job / "run.log").read_text(encoding="utf-8", errors="replace")
    progress = re.findall(r"^\+([0-9]+(?:\.[0-9]+)?)s\b", log, flags=re.M)
    if not progress or float(progress[-1]) < 89.9:
        raise RuntimeError(f"Seed {seed} did not reach 90-second end")
    for part in ("sim", "auth", "state"):
        folder = job / "P" / part
        if not any(p.is_file() for p in folder.rglob("*")):
            raise RuntimeError(f"Missing {part} results for seed {seed}")
    analyzer = analyzer_override or base / ANALYZER_REL
    if analyzer_override is None:
        registered_analyzer_sha = read_json(batch / "REGISTERED_PLAN.json")[
            "frozen_analyzer_sha256"
        ]
        if file_hash(analyzer) != registered_analyzer_sha:
            raise RuntimeError("Frozen analyzer changed after pre-registration")
    # Allow the frozen analyzer to import sibling helper modules unchanged.
    sys.path.insert(0, str(analyzer.parent))
    try:
        namespace = runpy.run_path(str(analyzer))
    finally:
        sys.path.pop(0)
    if not callable(namespace.get("run")):
        raise RuntimeError("Frozen analyzer has no run(root) entrypoint")
    result = namespace["run"](job)
    if not isinstance(result, dict) or not result.get("per_scheme"):
        raise RuntimeError("Frozen analyzer returned invalid report")
    save_json(job / "FORMAL_ANALYSIS.json", result)
    metric = result["per_scheme"][0]
    if metric.get("mode") != "P" or metric.get("n") != 500:
        raise RuntimeError(f"Seed {seed} analyzer changed scope")
    blockers = {k: v for k, v in metric.get("classification_counts", {}).items()
                if k in BLOCKERS and v}
    if not metric.get("measurement_valid") or blockers:
        raise RuntimeError(f"Seed {seed} invalid: evidence={metric.get('measurement_valid')}; "
                           f"blockers={blockers}")
    (job / "ANALYSIS_OK").write_text("VALIDATED\n", encoding="utf-8")
    return {"seed": seed,
            "full_mission_rate": metric.get("full_mission_rate"),
            "classification_counts": metric.get("classification_counts", {})}


def worker(base, batch, time_limit="48h", analyzer_override=None):
    try:
        with (batch / "worker_started.lock").open("x") as f:
            f.write(now())
        for wave_num, (first, second) in enumerate(((1, 2), (3, 4)), start=1):
            write_batch_state(batch, f"WAVE_{wave_num}_RUNNING",
                              seeds=[first, second])
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = {
                    seed: pool.submit(single_run, base, batch, seed, time_limit)
                    for seed in (first, second)
                }
                exits = {seed: task.result() for seed, task in futures.items()}
            if any(rc != 0 for rc in exits.values()):
                raise RuntimeError(f"Wave {wave_num} exits: {exits}")
            write_batch_state(batch, f"WAVE_{wave_num}_ANALYZING")
            reports = [analyze_run(base, batch, seed, analyzer_override)
                       for seed in (first, second)]
            save_json(batch / f"WAVE_{wave_num}_VERIFIED.json", reports)
        write_batch_state(batch, "FOUR_FORMAL_RUNS_VALIDATED",
                          note="Cloud original outputs still require Windows D: backup")
        return True
    except Exception as exc:
        write_batch_state(batch, "HALTED_NEEDS_ATTENTION",
                          error=str(exc))
        return False


def start():
    if os.geteuid() != 0:
        raise PermissionError("Cloud Assistant command requires root")
    batch = make_batch()
    cmd = [
        "systemd-run", "--unit=" + UNIT_NAME,
        "--property=Type=exec", "--property=MemoryMax=29G",
        "--setenv=HOME=/root",
        "/usr/bin/python3", str(batch / "orchestrator.py"), "worker",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode:
        write_batch_state(batch, "REGISTERED_BUT_SERVICE_NOT_STARTED",
                          error=result.stderr)
        raise RuntimeError(result.stderr.strip())
    print("REGISTERED_AND_SUBMITTED=" + str(batch))
    print(result.stdout.strip())
    print("STATUS: systemctl status " + UNIT_NAME + " --no-pager")
    print("STATE: cat " + str(batch / "STATE.json"))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("start", "worker"):
            raise ValueError("Usage: python3 e5b_n500_formal4.py start|worker")
        if sys.argv[1] == "start":
            start()
        else:
            ok = worker(BASE, BASE / "runs" / BATCH_NAME)
            sys.exit(0 if ok else 1)
    except Exception as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        sys.exit(1)
