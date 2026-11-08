#!/usr/bin/env python3
"""E2-DISTRIBUTED ABLATION - scene generator.

Builds the P-NET (networkized infrastructure) scenes for the E2 ablation:
  * HO12 : natural LTE A3-RSRP handover, cells 1->2 (HO1) and 2->3 (HO2).
           Uses the frozen-E2 radio topology, flight plan and A3Rsrp algorithm.
  * HO3  : independent controlled E-only scene. Same topology, shortened flight
           plan (the drone never leaves cell 1), no RRC handover, no G switch;
           one E-only logical target change ES_T1 -> ES_T2 at Ho3AtSec.

Compared with the E2B/P-NET reference template this generator ONLY changes
deployment/reproducibility knobs:
  - handover algorithm  : UavmaBiGatedA3HandoverAlgorithm -> A3RsrpHandoverAlgorithm
  - observer app        : BiMappedAuthApplication removed (BI-gated only)
  - Variant             : P | A_JOINT (trigger policy only)
  - AllowForcedSameSiteReauth : true only for A_JOINT
  - Ho3* attributes     : only for the HO3 scene, only on the UAV and the MM
  - output paths        : derived from the caller-supplied output root

No protocol field, message length, crypto parameter or cost table is touched.
"""
import argparse
import copy
import json
import hashlib
import os

E1_COSTS = ("target_create_session_M0_G=36.6614;uav_handle_M0_G=113.796;"
            "uav_build_M1_G=53.4401;target_handle_M1_G=128.109;uav_handle_M2_G=59.1432;"
            "target_handle_M3_G=1.29863;target_create_session_M0_E=36.0599;"
            "uav_handle_M0_E=116.186;uav_build_M1_E=53.278;target_handle_M1_E=124.508;"
            "uav_handle_M2_E=57.7765;target_handle_M3_E=1.57937")
E1_SHA = "98a572a844b17e7d82d1324de8a804ce9e26e7bcd271a2edce5a3e7e70ef84c6"
CELL_TO_EDGE = "1:ES_T1,2:ES_T1,3:ES_T2"
SITE_MAP = ("GS_CELL_1=200.0.0.2,GS_CELL_2=200.0.0.3,GS_CELL_3=200.0.0.4,"
            "ES_T1=200.0.0.4,ES_T2=200.0.0.5")

# Shortened HO3 flight plan, identical to the frozen E2 HO3 scene: the drone stays
# inside cell 1 (eNB at x=170) so no A3 event and therefore no G switch occurs.
HO3_FLIGHT_PLAN = [
    {"position": [80.0, 500.0, 30.0], "interest": 0, "restTime": 3.0},
    {"position": [200.0, 500.0, 30.0], "interest": 0},
]


def is_uavma(node):
    return isinstance(node, dict) and str(node.get("name", "")).startswith("ns3::Uavma")


def get_attr(app, name):
    for a in app.get("attributes", []):
        if a["name"] == name:
            return a
    return None


def set_attr(app, name, value):
    a = get_attr(app, name)
    if a is None:
        app.setdefault("attributes", []).append({"name": name, "value": value})
    else:
        a["value"] = value


def del_attr(app, name):
    app["attributes"] = [a for a in app.get("attributes", []) if a["name"] != name]


def walk_apps(doc):
    """Yield (path, app-dict) for every application entry in the scene."""
    out = []

    def rec(o, path):
        if isinstance(o, dict):
            if is_uavma(o):
                out.append((path, o))
            for k, v in o.items():
                rec(v, path + "/" + str(k))
        elif isinstance(o, list):
            for i, x in enumerate(o):
                rec(x, path + "[%d]" % i)

    rec(doc, "")
    return out


def strip_bi(doc):
    """Remove the BI-gated handover algorithm, its attributes and the BI observer."""
    keep = []
    for e in doc.get("staticNs3Config", []):
        n = e.get("name", "")
        if n.startswith("ns3::UavmaBiGatedA3HandoverAlgorithm"):
            continue
        if n == "ns3::LteHelper::HandoverAlgorithm":
            e["value"] = "ns3::A3RsrpHandoverAlgorithm"
        keep.append(e)
    doc["staticNs3Config"] = keep
    for d in doc.get("drones", []):
        d["applications"] = [a for a in d.get("applications", [])
                             if a.get("name") != "ns3::BiMappedAuthApplication"]


def build(template, out_root, event, variant, run, ho3_at=30.0, ho3_observe=2.0,
          log_on_file=True):
    doc = copy.deepcopy(template)
    # Base of the whole working tree. Every generated path is derived from the
    # caller-supplied root, so nothing can silently point at an existing run.
    # Portable: derive both roots from the caller-supplied output root.
    # E2_WIN_ROOT / E2_WSL_ROOT may be set when the simulation runs in WSL
    # from a Windows-mounted path.
    base_win = os.environ.get("E2_WIN_ROOT", os.path.abspath(out_root))
    base_wsl = os.environ.get("E2_WSL_ROOT", base_win.replace("\\", "/"))

    # Never reuse (and therefore never have to delete) an existing output directory:
    # a repeated smoke run gets a fresh, unique directory instead.
    run_dir = os.path.join(out_root, "r%02d" % run, event, variant)
    n = 1
    cand = run_dir
    while os.path.exists(cand):
        n += 1
        cand = "%s_%d" % (run_dir, n)
    run_dir = cand
    rel = os.path.relpath(run_dir, base_win).replace("\\", "/")
    win_dir = base_win + "/" + rel
    wsl_dir = base_wsl + "/" + rel

    doc["name"] = "E2D_%s_%s_RNG%02d_A3RSRP" % (event, variant, run)
    doc["resultsPath"] = wsl_dir + "/sim/"
    doc["logOnFile"] = bool(log_on_file)
    os.makedirs(run_dir, exist_ok=True)
    for sub in ("sim", "state"):
        os.makedirs(os.path.join(run_dir, sub), exist_ok=True)

    strip_bi(doc)

    if event == "HO3":
        d = doc["drones"][0]
        for a in d["mobilityModel"].get("attributes", []):
            if a["name"] == "FlightPlan":
                a["value"] = copy.deepcopy(HO3_FLIGHT_PLAN)

    for idx, (path, app) in enumerate(walk_apps(doc)):
        role = get_attr(app, "Role")
        role = role["value"] if role else ""
        host = get_attr(app, "HostTargets")
        host = host["value"] if host else ""
        set_attr(app, "Variant", variant)
        set_attr(app, "E1HandlerCostsUs", E1_COSTS)
        set_attr(app, "E1ProfileSha256", E1_SHA)
        set_attr(app, "CpuResourceMode", "PER_DOMAIN")
        set_attr(app, "SiteMap", SITE_MAP)
        # Only the UAV and the MM evaluate the serving-cell -> target mapping. A P-NET
        # SITE must NOT carry CellToEdgeMap (the application rejects it), exactly as in
        # the reference P-NET deployment.
        if role in ("UAV", "MM"):
            set_attr(app, "CellToEdgeMap", CELL_TO_EDGE)
            set_attr(app, "InitialCellId", 1)
        else:
            del_attr(app, "CellToEdgeMap")
            del_attr(app, "InitialCellId")
        set_attr(app, "OutputPrefix", wsl_dir + "/uavma")
        # M2 is only meaningful for A_JOINT and is off for P, so P stays identical
        # to the legacy deployment behaviour.
        set_attr(app, "AllowForcedSameSiteReauth", variant == "A_JOINT")

        if role == "UAV":
            db = "uav"
        elif role == "MM":
            db = "mm"
        else:
            tag = host.replace(":", "_").replace(",", "_") or ("site%d" % idx)
            db = "site_" + tag
        set_attr(app, "StorePath", wsl_dir + "/state/%s.db" % db)

        if event == "HO3" and role in ("UAV", "MM"):
            set_attr(app, "Ho3AtSec", ho3_at)
            set_attr(app, "Ho3ObserveSec", ho3_observe)
            set_attr(app, "Ho3NewETarget", "ES_T2")
        else:
            del_attr(app, "Ho3AtSec")
            del_attr(app, "Ho3ObserveSec")
            del_attr(app, "Ho3NewETarget")

    scene_path = os.path.join(run_dir, "scene.json")
    with open(scene_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    with open(scene_path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return {"event": event, "variant": variant, "rng_run": run,
            "scene": scene_path, "scene_sha256": sha,
            "out_dir": run_dir, "win_dir": win_dir, "wsl_dir": wsl_dir,
            "log_on_file": bool(log_on_file)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--runs", default="3")
    ap.add_argument("--events", default="HO12,HO3")
    ap.add_argument("--variants", default="P,A_JOINT")
    ap.add_argument("--manifest", default=None)
    # logOnFile is the single master switch for ALL file-side capture in IoD-Sim
    # (internet/LTE pcap, ascii traces, PHY traces, scenario report). It gates
    # reporting only and never touches the network model or the protocol, so
    # turning it off is a pure output-volume control.
    ap.add_argument("--no-capture", action="store_true",
                    help="set logOnFile=false: keep CSV/ledger evidence, drop pcap/trace")
    # A fresh, timestamped output tree for every generation. An interrupted run
    # leaves partial files behind, and the application refuses to overwrite them;
    # stamping means a re-run never touches (and never has to delete) prior output.
    ap.add_argument("--stamp", default=None,
                    help="output sub-directory stamp (default: current UTC time)")
    a = ap.parse_args()
    if a.stamp is None:
        import datetime
        a.stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    a.root = os.path.join(a.root, a.stamp)

    runs = [int(x) for x in a.runs.split(",") if x.strip()]
    events = [x.strip() for x in a.events.split(",") if x.strip()]
    variants = [x.strip() for x in a.variants.split(",") if x.strip()]
    with open(a.template, "r", encoding="utf-8") as f:
        template = json.load(f)

    rows = []
    for r in runs:
        for ev in events:
            for v in variants:
                rows.append(build(template, a.root, ev, v, r,
                              log_on_file=not a.no_capture))
    man = a.manifest or os.path.join(a.root, "SCENE_MANIFEST.json")
    with open(man, "w", encoding="utf-8") as f:
        json.dump({"generated": rows}, f, indent=2)
    for r in rows:
        print("%-5s %-8s run=%02d  %s" % (r["event"], r["variant"], r["rng_run"],
                                          r["scene_sha256"][:16]))


if __name__ == "__main__":
    main()
