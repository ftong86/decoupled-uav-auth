#!/usr/bin/env python3
"""Build *real* multi-UAV E5 scenes from the frozen E2 P/A_JOINT templates.

N drone nodes + N pair-isolated target applications on ONE shared remote
infrastructure node. Each target gets independent protocol state and UDP port;
all targets share the infrastructure's *modeled CPU lanes* through E5 extension.
P/A scenarios use identical UAV placement, ports, identity and path semantics.
This script creates only NEW output files; it NEVER modifies the templates.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

PROTOCOL = "ns3::UavmaAuthApplication"
CLIENT_BG = "ns3::TcpStorageClientApplication"
BASE_PORT = 10000
STRIDE = 2
MAX_UAV = 500


def die(reason):
    raise ValueError(reason)


def get_attr(app, key):
    hits = [a for a in app.get('attributes', []) if a.get('name') == key]
    if len(hits) != 1:
        die(f"expected one {key} in {app.get('name')}, got {len(hits)}")
    return hits[0]['value']


def set_attr(app, key, value):
    hits = [a for a in app.get('attributes', []) if a.get('name') == key]
    if len(hits) > 1:
        die(f"duplicate {key} in {app.get('name')}")
    if hits:
        hits[0]['value'] = value
    else:
        app.setdefault('attributes', []).append({'name': key, 'value': value})


def get_app(node, name=PROTOCOL):
    hits = [app for app in node.get('applications', []) if app.get('name') == name]
    if len(hits) != 1:
        die(f"expected exactly one {name}, got {len(hits)}")
    return hits[0]


def source_ref(args):
    return {'p_template': str(args.p_template.resolve()),
            'a_joint_template': str(args.joint_template.resolve()),
            'p_sha256': hashlib.sha256(args.p_template.read_bytes()).hexdigest(),
            'a_joint_sha256': hashlib.sha256(args.joint_template.read_bytes()).hexdigest()}


def validate_template(s, mode):
    if len(s.get('drones', [])) != 1 or len(s.get('remotes', [])) != 1:
        die(f'{mode} template must be E2 single-drone, single-remote baseline')
    if len(s.get('ZSPs', [])) != 3 or not s.get('phyLayer'):
        die('expected real three-cell LTE scene')
    uav = get_app(s['drones'][0]); server = get_app(s['remotes'][0])
    if get_attr(uav, 'Role') != 'UAV' or get_attr(server, 'Role') != 'TARGET':
        die('UAV/TARGET role mismatch')
    if get_attr(uav, 'Variant') != mode or get_attr(server, 'Variant') != mode:
        die('template mode does not match requested P/A_JOINT')
    if get_attr(uav, 'CellToEdgeMap') != get_attr(server, 'CellToEdgeMap'):
        die('UAV/TARGET cell map mismatch')
    if not any(app.get('name') == 'ns3::UavmaAuthApplication' for app in s['drones'][0]['applications']):
        die('authentication application missing')
    return uav, server


def shifted_flightplan(original, idx, spread):
    obj = copy.deepcopy(original)
    attrs = obj['mobilityModel']['attributes']
    flight = [v for v in attrs if v.get('name') == 'FlightPlan']
    if len(flight) != 1:
        die('expected exactly one FlightPlan')
    # Deterministic nested deployment: UAV-0001 retains the same trajectory
    # whether N=1,10,...500, and both variants use identical spatial layouts.
    if idx == 0:
        offset_y = 0.0
    else:
        digest = hashlib.sha256(f'E5-uav-placement-{idx}'.encode()).digest()
        fraction = int.from_bytes(digest[:8], 'big') / ((1 << 64) - 1)
        offset_y = (fraction - 0.5) * 2 * spread
    for stop in flight[0]['value']:
        coords = stop['position']
        if len(coords) != 3:
            die('expected xyz waypoints')
        coords[1] = round(float(coords[1]) + offset_y, 7)
    return obj


def generate(template, mode, n, run_dir, spread_y_m, background_traffic):
    s = copy.deepcopy(template)
    single_uav, single_infra = validate_template(s, mode)
    original_drone = s['drones'][0]
    original_remote = s['remotes'][0]
    reference_peer = get_attr(single_uav, 'PeerIp')
    if reference_peer != '200.0.0.1':
        die(f'unexpected E2 backbone target IP {reference_peer}')
    if BASE_PORT + STRIDE * (n-1) + 1 >= 65535:
        die('port namespace overflow')
    target_attr_list = original_remote['applications']
    server_other = [copy.deepcopy(a) for a in target_attr_list if a.get('name') != PROTOCOL]
    remotes_auth = []
    drones = []
    for idx in range(n):
        name = f'uav{idx+1:04d}'
        port = BASE_PORT + STRIDE * idx
        trigger = port + 1
        seed_tag = f'e5-{name}'
        drone = shifted_flightplan(original_drone, idx, spread_y_m)
        auth = get_app(drone)
        set_attr(auth, 'SeedTag', seed_tag)
        set_attr(auth, 'PeerIp', reference_peer)
        set_attr(auth, 'PeerPort', port)
        set_attr(auth, 'LocalPort', 9000)
        set_attr(auth, 'TriggerPort', trigger)
        set_attr(auth, 'OutputPrefix', str(run_dir / 'auth' / name))
        set_attr(auth, 'StorePath', str(run_dir / 'state' / f'{name}-uav.db'))
        set_attr(auth, 'Variant', mode)
        if not background_traffic:
            drone['applications'] = [a for a in drone['applications'] if a.get('name') != CLIENT_BG]
        drones.append(drone)

        target = copy.deepcopy(single_infra)
        set_attr(target, 'SeedTag', seed_tag)
        set_attr(target, 'PeerPort', 9000)
        set_attr(target, 'LocalPort', port)
        set_attr(target, 'TriggerPort', trigger)
        set_attr(target, 'OutputPrefix', str(run_dir / 'auth' / name))
        set_attr(target, 'StorePath', str(run_dir / 'state' / f'{name}-infra.db'))
        set_attr(target, 'Variant', mode)
        set_attr(target, 'E5SharedInfraCpu', True)
        remotes_auth.append(target)
    s['drones'] = drones
    s['remotes'] = [copy.deepcopy(original_remote)]
    s['remotes'][0]['applications'] = server_other + remotes_auth
    s['name'] = f'E5_real_{n}_UAV_{mode}'
    s['resultsPath'] = str(run_dir / 'sim') + '/'
    return s


def ensure_allowed_out_root(path):
    resolved = path.resolve()
    name = str(resolved).lower()
    forbidden = ('uav-iodsim-build', 'uav-e4-build', 'e4_formal_raw',
                 'e4_formal_archive', 'paper_experiment_data', 'e2-clean-r03')
    if any(x in name for x in forbidden):
        die('refusing to create E5 scenes inside frozen code or results')
    return resolved


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--p-template', type=Path, required=True)
    p.add_argument('--joint-template', type=Path, required=True)
    p.add_argument('--out-root', type=Path, required=True)
    p.add_argument('--n', type=int, required=True)
    p.add_argument('--rng-seed', type=int, required=True)
    p.add_argument('--rng-run', type=int, default=1)
    p.add_argument('--spread-y-m', type=float, default=70.0)
    p.add_argument('--background-traffic', action='store_true',
                   help='Include original E2 TCP application load (default: auth-only)')
    args = p.parse_args()
    if not (1 <= args.n <= MAX_UAV):
        die(f'N must be 1..{MAX_UAV}')
    if args.rng_seed < 1 or args.rng_run < 1:
        die('positive RngSeed/RngRun required')
    if not (0 <= args.spread_y_m <= 100):
        die('spread-y-m must be 0..100 meters to stay near verified flight corridor')
    ref = source_ref(args)
    outroot = ensure_allowed_out_root(args.out_root)
    root = outroot / f'N{args.n:03d}_seed{args.rng_seed:03d}_run{args.rng_run:03d}'
    if root.exists():
        die(f'refusing to overwrite existing E5 output {root}')
    templates = {'P':json.loads(args.p_template.read_text()),
                 'A_JOINT':json.loads(args.joint_template.read_text())}
    # Runtime parameters are controlled by ns-3 command-line (not by editing
    # static E2/E4 configuration): --RngSeed and --RngRun.
    root.mkdir(parents=True)
    for mode in ('P','A_JOINT'):
        rundir = root / mode
        (rundir / 'auth').mkdir(parents=True)
        (rundir / 'state').mkdir(parents=True)
        (rundir / 'sim').mkdir(parents=True)
        scene = generate(templates[mode], mode, args.n, rundir,
                         args.spread_y_m,args.background_traffic)
        (rundir / 'scene.json').write_text(json.dumps(scene, indent=2,ensure_ascii=False)+'\n')
    metadata = {
        'kind':'E5_DEVELOPMENT_ONLY',
        'n_uav':args.n,
        'rng_seed':args.rng_seed,
        'rng_run':args.rng_run,
        'variant':['P','A_JOINT'],
        'cpu_model':'shared infra node modeled CPU pool; PER_DOMAIN G/E lanes',
        'authentication_isolation':'one UavmaAuthApplication instance per UAV on same remote node; unique target port and SeedTag',
        'background_traffic':args.background_traffic,
        'spread_y_m':args.spread_y_m,
        'input_files':ref,
        'verification_status':'NOT_RUN_NS3; no claims of successful concurrent auth',
        'formal_data':False,
    }
    (root / 'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps({'status':'SCENES_CREATED_ONLY','out_root':str(root),
        'total_drones':args.n,'target_auth_applications':args.n,
        'simulator_tested':False,'formal':False},indent=2))

if __name__=='__main__':
    main()
