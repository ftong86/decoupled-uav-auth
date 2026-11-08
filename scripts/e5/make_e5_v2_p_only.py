#!/usr/bin/env python3
"""Generate ONLY P-mode E5-B scaled LTE scene with verified E5-V2 build().

No A_JOINT scenario, process, application, or file is generated. Reuse the
unmodified validated E5-V2 three-cell-per-cluster construction unchanged.
"""
import json
from pathlib import Path

from make_e5_v2_scenes import build, check, fingerprint, guarded_root


def generate_p_only(p_template, out_root, n, seed, run, layout='scaled',
                    per_cluster=25, spacing_m=2500., spread_y_m=70.,
                    background=False):
    check(seed >= 1 and run >= 1, 'seed and run must be positive')
    check(layout == 'scaled', 'P-only formal suite permits scaled layout only')
    check(background is False, 'P-only formal suite prohibits background change')
    root = guarded_root(Path(out_root))
    name = f'E5V2_{layout}_N{n:04d}_C{per_cluster:03d}_seed{seed:03d}_run{run:03d}'
    dest = root / name
    check(not dest.exists(), f'refusing overwrite of existing formal run {dest}')
    template = Path(p_template)
    scene = json.loads(template.read_text(encoding='utf-8'))
    planned, catalog = build(scene, 'P', n, dest / 'P', layout,
                             per_cluster, spacing_m, spread_y_m, background)
    check(len(planned['drones']) == n, 'incorrect UAV count')
    check(len(planned['ZSPs']) == 3*len(catalog), 'incorrect LTE eNB count')
    check(len(planned['remotes']) == 1, 'shared infrastructure topology drift')
    # Complete validation precedes all filesystem mutation.
    dest.mkdir(parents=True, exist_ok=False)
    (dest / 'P').mkdir(exist_ok=False)
    for name_sub in ('auth', 'state', 'sim'):
        (dest / 'P' / name_sub).mkdir(exist_ok=False)
    (dest / 'P' / 'scene.json').write_text(
        json.dumps(planned, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    manifest = {
        'kind': 'E5_V2_DEVELOPMENT_ONLY', 'formal': False,
        'layout': layout, 'n_uav': n, 'uav_per_cluster': per_cluster,
        'effective_uav_per_cluster': per_cluster,
        'cluster_count': len(catalog), 'enb_count': 3 * len(catalog),
        'radio_network': 'single LTE stack with geographically separated 3-cell clusters; X2 links within cluster only',
        'core_network': 'one original EPC/remote and one shared modeled target CPU pool for N logical TARGET applications',
        'auth_semantics': 'real LTE handover -> partition event -> independent G/E auth, no synthetic trigger',
        'variant': ['P'], 'rng_seed': seed, 'rng_run': run,
        'spacing_m': spacing_m, 'spread_y_m': spread_y_m,
        'background_traffic': background,
        'simulation_duration_sec': planned['duration'],
        'site_catalog': catalog, 'inputs': fingerprint({'P': template}),
        'cell_ids_assumed': 'eNB CellId assigned sequentially by IoD-Sim ns-3; MUST verify against actual RRC logs',
        'status': 'NOT_RUN_NS3',
        'formal_scope': 'P_ONLY; NO A_JOINT DATA OR SIMULATION',
    }
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    return {'status':'P_SCENE_CREATED_ONLY','run_root':str(dest),
            'uav':n, 'enb':3*len(catalog), 'clusters':len(catalog), 'tested_ns3':False}
