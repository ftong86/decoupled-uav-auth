#!/usr/bin/env python3
"""UAVMA E5 V2: multi-corridor *real LTE* topology generation.

Fixed: N UEs share the E2 three-cell corridor (radio-load experiment).
Scaled: ceil(N / uavs_per_cluster) independent geographic corridors of
       3 LTE eNBs, with each UAV following the frozen three-waypoint path.

Each UAV has a real ns-3 Drone/UE, per-UAV target app, independent security
state/ports/DB; all target apps share ONE modeled infrastructure CPU pool.
No injected/synthetic authentication, network events or service migration.
This tool never touches E2/E4/old E5 files and never overwrites outputs.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path

AUTH = 'ns3::UavmaAuthApplication'
BG_CLIENT = 'ns3::TcpStorageClientApplication'
BASE_PORT = 10000
MAX_UAV = 1000


def check(predicate, message):
    if not predicate:
        raise ValueError(message)


def attr(app, key):
    found = [a for a in app.get('attributes', []) if a.get('name') == key]
    check(len(found) == 1, f'exactly one {key} required in {app.get("name")}')
    return found[0]['value']


def put(app, key, value):
    found = [a for a in app.get('attributes', []) if a.get('name') == key]
    check(len(found) < 2, f'duplicate {key}')
    if found:
        found[0]['value'] = value
    else:
        app.setdefault('attributes', []).append({'name': key, 'value': value})


def get_app(node, application=AUTH):
    found = [a for a in node.get('applications', []) if a.get('name') == application]
    check(len(found) == 1, f'exactly one {application} app required')
    return found[0]


def value_attr(node, key):
    attrs = node['mobilityModel']['attributes']
    matches = [a for a in attrs if a.get('name') == key]
    check(len(matches) == 1, f'exactly one {key} mobility value required')
    return matches[0]['value']


def validate_base(scene, mode):
    check(len(scene.get('drones', [])) == 1, 'frozen template must have 1 drone')
    check(len(scene.get('ZSPs', [])) == 3, 'frozen template must have exactly 3 eNBs')
    check(len(scene.get('remotes', [])) == 1, 'frozen template must have 1 remote')
    check(len(scene.get('phyLayer', [])) == 1 and
          scene['phyLayer'][0].get('type') == 'lte', 'must be the baseline LTE PHY')
    check(len(scene.get('networkLayer', [])) == 1, 'must use one baseline LTE network')
    ua = get_app(scene['drones'][0])
    ia = get_app(scene['remotes'][0])
    check(attr(ua, 'Role') == 'UAV' and attr(ia, 'Role') == 'TARGET', 'auth roles mismatch')
    check(attr(ua, 'Variant') == mode and attr(ia, 'Variant') == mode, 'mode mismatch')
    check(attr(ua, 'CellToEdgeMap') == '1:ES_T1,2:ES_T1,3:ES_T2',
          'unexpected UAV original cell map')
    check(attr(ia, 'CellToEdgeMap') == attr(ua, 'CellToEdgeMap'), 'cell maps mismatch')
    check(attr(ua, 'InitialCellId') == 1 and attr(ia, 'InitialCellId') == 1,
          'baseline first cell != 1')
    check(attr(ua, 'GTargetId') == 'GS_CELL_1', 'unexpected initial G target')
    check(attr(ia, 'GTargetId') == 'GS_CELL_1', 'unexpected infra initial G target')
    check(attr(ua, 'ETargetId') == 'ES_T1' and attr(ia, 'ETargetId') == 'ES_T1',
          'unexpected initial E target')
    check(attr(ua, 'PeerIp') == '200.0.0.1', 'unexpected E2 single-remote peer IP')
    coords = [value_attr(enb, 'Position') for enb in scene['ZSPs']]
    check(len(coords) == 3 and all(len(c) == 3 for c in coords),
          'missing reference eNB positions')
    flight = value_attr(scene['drones'][0], 'FlightPlan')
    check(len(flight) == 3 and all(len(p['position']) == 3 for p in flight),
          'expected 3 fixed waypoints')
    check(scene['world'].get('size') is not None, 'missing world dimension')
    return True


def fingerprint(files):
    return {key: {'path': str(path.resolve()),
                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            for key, path in files.items()}


def offsets(index, per_cluster, spread):
    local_idx = index % per_cluster
    if local_idx == 0 or spread == 0:
        return 0.0
    # Stable across N and across P/A_JOINT; first UE in EACH site group at center.
    digest = hashlib.sha256(f'E5-V2-placement-{index}'.encode()).digest()
    fraction = int.from_bytes(digest[:8], 'big') / ((1 << 64) - 1)
    return round((fraction - 0.5) * 2 * spread, 7)


def site_mapping(group_index):
    cell0 = group_index * 3 + 1
    # Preserve literal E2 target IDs for the first group, scope later groups.
    suffix = '' if group_index == 0 else f'_SITE{group_index+1:03d}'
    edge_a = 'ES_T1' + suffix
    edge_b = 'ES_T2' + suffix
    return {
        'cells': (cell0, cell0 + 1, cell0 + 2),
        'map': f'{cell0}:{edge_a},{cell0+1}:{edge_a},{cell0+2}:{edge_b}',
        'g_id': f'GS_CELL_{cell0}',
        'e_id': edge_a,
        'edges': (edge_a, edge_b),
    }


def build(scene, mode, n, run_dir, layout, per_cluster, gap, spread, background):
    scene = copy.deepcopy(scene)
    validate_base(scene, mode)
    check(1 <= n <= MAX_UAV, 'N out of 1..1000')
    check(per_cluster >= 1 and per_cluster <= 100, 'uavs_per_cluster out of 1..100')
    check(1000 <= gap <= 20000, 'site spacing out of 1000..20000 m')
    check(0 <= spread <= 100, 'spread out of 0..100 m')
    check(BASE_PORT + 2 * (n - 1) + 1 <= 65535, 'port overflow')
    check(layout in ('fixed', 'scaled'), 'invalid layout')
    effective_group_size = n if layout == 'fixed' else per_cluster
    count = math.ceil(n / effective_group_size)
    check(3 * count <= 65535, 'LTE cell ID overflow')
    source_enbs = scene['ZSPs']
    base_drone = scene['drones'][0]
    base_remote = scene['remotes'][0]
    template_uav = get_app(base_drone)
    template_target = get_app(base_remote)
    other_server_apps = [copy.deepcopy(a) for a in base_remote['applications']
                         if a.get('name') != AUTH]

    cells = []
    site_catalog = []
    for group in range(count):
        details = site_mapping(group)
        offset_y = group * gap
        for local_enb, enb in enumerate(source_enbs):
            site = copy.deepcopy(enb)
            p = value_attr(site, 'Position')
            p[1] = round(float(p[1]) + offset_y, 7)
            cells.append(site)
        site_catalog.append({'cluster_id': group + 1, 'cells': list(details['cells']),
                             'cell_to_edge_map': details['map'],
                             'edge_ids': list(details['edges']),
                             'y_offset_m': offset_y,
                             'nominal_enb_order': list(range(group*3+1, group*3+4))})
    scene['ZSPs'] = cells
    # Preserve X/Z extents and all mobility/PHY parameters; just enlarge Y world.
    old_y = float(scene['world']['size']['Y'])
    new_y = max(old_y, old_y + (count - 1) * gap)
    check(math.isfinite(new_y) and new_y < 5e6, 'world extent exceeds safe bounds')
    scene['world']['size']['Y'] = str(int(new_y)) if new_y.is_integer() else str(new_y)

    drones = []
    target_apps = []
    for idx in range(n):
        ident = f'uav{idx+1:04d}'
        group = idx // effective_group_size
        info = site_mapping(group)
        port, trigger = BASE_PORT + 2 * idx, BASE_PORT + 2 * idx + 1
        seed_tag = 'e5-' + ident
        y_delta = group * gap + offsets(idx, effective_group_size, spread)
        drone = copy.deepcopy(base_drone)
        for point in value_attr(drone, 'FlightPlan'):
            point['position'][1] = round(float(point['position'][1]) + y_delta, 7)
        ua = get_app(drone)
        for k, val in (
            ('SeedTag', seed_tag), ('PeerIp', '200.0.0.1'),
            ('PeerPort', port), ('LocalPort', 9000), ('TriggerPort', trigger),
            ('OutputPrefix', str(run_dir / 'auth' / ident)),
            ('StorePath', str(run_dir / 'state' / (ident + '-uav.db'))),
            ('Variant', mode), ('CellToEdgeMap', info['map']),
            ('InitialCellId', info['cells'][0]),
            ('GTargetId', info['g_id']), ('ETargetId', info['e_id'])):
            put(ua, k, val)
        if not background:
            drone['applications'] = [a for a in drone['applications']
                                     if a.get('name') != BG_CLIENT]
        drones.append(drone)

        ta = copy.deepcopy(template_target)
        for k, val in (
            ('SeedTag', seed_tag), ('PeerPort', 9000),
            ('LocalPort', port), ('TriggerPort', trigger),
            ('OutputPrefix', str(run_dir / 'auth' / ident)),
            ('StorePath', str(run_dir / 'state' / (ident + '-infra.db'))),
            ('Variant', mode), ('CellToEdgeMap', info['map']),
            ('InitialCellId', info['cells'][0]),
            ('GTargetId', info['g_id']), ('ETargetId', info['e_id']),
            ('E5SharedInfraCpu', True)):
            put(ta, k, val)
        target_apps.append(ta)
    scene['drones'] = drones
    scene['remotes'] = [copy.deepcopy(base_remote)]
    scene['remotes'][0]['applications'] = other_server_apps + target_apps
    scene['name'] = f'E5V2_{layout}_N{n}_{mode}_{count}_clusters'
    scene['resultsPath'] = str(run_dir / 'sim') + '/'
    return scene, site_catalog


def guarded_root(p):
    p = p.resolve(strict=False)
    # Must be an independent E5-V2 run location, never a frozen source tree.
    s = str(p).lower()
    for forbidden in ('uav-iodsim-build', 'uav-e4-build', 'e4_formal',
                      'e2-clean-r03', 'paper_experiment_data'):
        check(forbidden not in s, f'output under protected location {forbidden}')
    return p


def generate_pair(p_template, joint_template, out_root, n, seed, run, layout,
                  per_cluster=25, spacing_m=2500., spread_y_m=70., background=False):
    check(seed >= 1 and run >= 1, 'seed and run must be positive')
    root = guarded_root(out_root)
    name = f'E5V2_{layout}_N{n:04d}_C{per_cluster:03d}_seed{seed:03d}_run{run:03d}'
    dest = root / name
    check(not dest.exists(), f'refusing overwrite of existing E5 V2 run {dest}')
    inputs = {'P': p_template, 'A_JOINT': joint_template}
    references = fingerprint(inputs)
    scenes, mapping = {}, None
    for mode, path in inputs.items():
        s = json.loads(path.read_text(encoding='utf-8'))
        view = dest / mode
        built, catalog = build(s, mode, n, view, layout, per_cluster,
                               spacing_m, spread_y_m, background)
        scenes[mode] = built
        if mapping is None:
            mapping = catalog
        else:
            check(mapping == catalog, 'P/A site assignments differ')
    check([x['mobilityModel'] for x in scenes['P']['drones']] ==
          [x['mobilityModel'] for x in scenes['A_JOINT']['drones']],
          'P/A movement mismatch')
    check([x['mobilityModel'] for x in scenes['P']['ZSPs']] ==
          [x['mobilityModel'] for x in scenes['A_JOINT']['ZSPs']],
          'P/A eNB placement mismatch')

    # All validation above precedes any filesystem mutation.
    dest.mkdir(parents=True, exist_ok=False)
    for mode in ('P', 'A_JOINT'):
        view = dest / mode
        for name_sub in ('auth','state','sim'):
            (view / name_sub).mkdir(parents=True, exist_ok=False)
        (view / 'scene.json').write_text(json.dumps(scenes[mode], indent=2,
                              ensure_ascii=False)+'\n', encoding='utf-8')
    manifest = {
        'kind': 'E5_V2_DEVELOPMENT_ONLY', 'formal': False,
        'layout': layout, 'n_uav': n, 'uav_per_cluster': per_cluster,
        'effective_uav_per_cluster': n if layout == 'fixed' else per_cluster,
        'cluster_count': len(mapping), 'enb_count': 3 * len(mapping),
        'radio_network': 'single LTE stack with geographically separated 3-cell clusters; X2 links within cluster only',
        'core_network': 'one original EPC/remote and one shared modeled target CPU pool for N logical TARGET applications',
        'auth_semantics': 'real LTE handover -> partition event -> independent G/E auth, no synthetic trigger',
        'variant': ['P', 'A_JOINT'], 'rng_seed': seed, 'rng_run': run,
        'spacing_m': spacing_m, 'spread_y_m': spread_y_m,
        'background_traffic': background, 'simulation_duration_sec': scenes['P']['duration'],
        'site_catalog': mapping, 'inputs': references,
        'cell_ids_assumed': 'eNB CellId assigned sequentially by IoD-Sim ns-3; MUST verify against actual RRC logs',
        'status': 'NOT_RUN_NS3',
    }
    (dest / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    return {'status': 'SCENES_CREATED_ONLY', 'run_root': str(dest), 'uav': n,
            'enb': 3*len(mapping), 'clusters': len(mapping), 'tested_ns3': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--p-template',type=Path,required=True)
    p.add_argument('--joint-template',type=Path,required=True)
    p.add_argument('--out-root',type=Path,required=True)
    p.add_argument('--n',type=int,required=True)
    p.add_argument('--rng-seed',type=int,default=33)
    p.add_argument('--rng-run',type=int,default=3)
    p.add_argument('--layout',choices=('fixed','scaled'),default='scaled')
    p.add_argument('--uavs-per-cluster',type=int,default=25)
    p.add_argument('--site-spacing-m',type=float,default=2500.)
    p.add_argument('--spread-y-m',type=float,default=70.)
    p.add_argument('--background-traffic',action='store_true')
    args = p.parse_args()
    result = generate_pair(args.p_template,args.joint_template,args.out_root,
                           args.n,args.rng_seed,args.rng_run,args.layout,
                           args.uavs_per_cluster,args.site_spacing_m,
                           args.spread_y_m,args.background_traffic)
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
