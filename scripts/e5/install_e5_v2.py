#!/usr/bin/env python3
"""SHA-guarded E5 V2 source overlay. NEVER installs into E2/E4/E5 V1 trees.

Default is dry-run. --apply is permitted only on an independent, copied E5 V2
source tree; changes are limited to IoD_Sim/src/main.cc and E5 transport.cc.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

PROJECT_ROOT = Path('/home/wang/uav-e5-v2-build/IoD_Sim')
MODULE = PROJECT_ROOT / 'ns3/contrib/uavma'
E2_SO = Path('/home/wang/uav-iodsim-build/IoD_Sim/ns3/build/lib/libns3.45-uavma-debug.so')
E4_SO = Path('/home/wang/uav-e4-build/IoD_Sim/ns3/build/lib/libns3.45-uavma-debug.so')
FROZEN = {
    E2_SO: '770ff638d3db92458924a22ec4e6a1dfd89586198809515a386a1638fc57cd6d',
    E4_SO: '3da822d834f428ca2811f6510ee28a9360484a071e0785c722e24b4e287a4bc0',
}
ARTIFACTS = {
    'src/main.cc': {
        'before': '29207b892b206216bd660ad3114b1b2a23c98117d670c4655faab33040e049d6',
        'after': '60149321c47c4d66788a18ef6d673684f866a23bad96500203c7091c41ef6d30',
        'payload': 'patches/main.cc',
    },
    'ns3/contrib/uavma/model/uavma-ns3-transport.cc': {
        'before': '3617f78095a3f22847ee38f69d181c2b4718f78acfb7bffc5b9904737c67c633',
        'after': '23ffa00899dd662f813c0f812c95faa5df3b3938d688bd70dd363e57d9b47120',
        'payload': 'patches/uavma-ns3-transport.cc',
    },
}


def sha256(path):
    if not path.is_file():
        raise ValueError(f'Missing expected regular file: {path}')
    h = hashlib.sha256()
    with path.open('rb') as f:
        for buf in iter(lambda: f.read(1024 * 1024), b''):
            h.update(buf)
    return h.hexdigest()


def safe_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f'Refusing link/non-regular source: {path}')
    if path.is_symlink():
        raise ValueError(f'Refusing symlink source: {path}')
    return info


def prepare_plan(module_dir, package_dir, frozen=FROZEN, project=PROJECT_ROOT):
    # Expected location is intentionally fixed to prevent wrong-tree writes.
    if module_dir != MODULE or module_dir.resolve(strict=True) != MODULE:
        raise ValueError(f'Module must be {MODULE}; got {module_dir}')
    if project.resolve(strict=True) != PROJECT_ROOT:
        raise ValueError('Unexpected E5 V2 project root')
    if project.is_symlink() or module_dir.is_symlink():
        raise ValueError('Independent E5 V2 root is a symlink')
    if any(s in str(module_dir).lower() for s in ('uav-iodsim-build','uav-e4-build')):
        raise ValueError('Frozen source-tree path detected')
    freeze_digests = {}
    for path, expected in frozen.items():
        actual = sha256(path)
        freeze_digests[str(path)] = actual
        if actual != expected:
            raise ValueError(f'Frozen baseline drift: {path}: {actual}')
    actions = []
    for key, config in ARTIFACTS.items():
        target = project / key
        payload = package_dir / config['payload']
        safe_file(target)
        safe_file(payload)
        if target.resolve(strict=True) != target or payload.resolve(strict=True) != payload:
            raise ValueError('Unexpected symlink/indirection on source path')
        before = sha256(target)
        proposed = sha256(payload)
        if proposed != config['after']:
            raise ValueError(f'Package payload SHA mismatch: {payload}')
        if before not in (config['before'], config['after']):
            raise ValueError(f'Unknown installed source revision: {key}: {before}')
        actions.append({ 'target': str(target), 'before_sha256': before,
                         'after_sha256': proposed,
                         'changed': before != proposed,
                         'payload': str(payload) })
    return { 'status': 'READY', 'module_dir': str(module_dir),
             'frozen_sha256': freeze_digests, 'actions': actions }


def apply(plan, backup_root):
    changed = [r for r in plan['actions'] if r['changed']]
    if not changed:
        return {'status': 'ALREADY_INSTALLED', 'backup': None}
    if backup_root.exists():
        raise ValueError(f'Backup root already exists: {backup_root}')
    # Verify that all targets are STILL in their expected state before writing.
    for rec in plan['actions']:
        if sha256(Path(rec['target'])) != rec['before_sha256']:
            raise ValueError(f'Concurrent changes to {rec["target"]}')
    backup_root.mkdir(parents=True, exist_ok=False)
    # Save original bytes BEFORE changing anything; names mirror IoD_Sim tree.
    for rec in changed:
        target = Path(rec['target'])
        rel = target.relative_to(PROJECT_ROOT)
        backup = backup_root / rel
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, backup)
    installed = []
    try:
        for rec in changed:
            target, src = Path(rec['target']), Path(rec['payload'])
            with tempfile.NamedTemporaryFile(mode='wb', dir=target.parent,
                                             prefix='.e5-v2-tmp-', delete=False) as f:
                tmp = Path(f.name)
                f.write(src.read_bytes())
            try:
                os.chmod(tmp, target.stat().st_mode)
                os.replace(tmp, target)
            finally:
                if tmp.exists():
                    tmp.unlink()
            if sha256(target) != rec['after_sha256']:
                raise ValueError(f'Postinstall SHA drift: {target}')
            installed.append(rec)
        for path, expected in FROZEN.items():
            if sha256(path) != expected:
                raise ValueError(f'Postinstall frozen artifact changed: {path}')
    except Exception:
        for rec in installed:
            target = Path(rec['target'])
            backup = backup_root / target.relative_to(PROJECT_ROOT)
            shutil.copy2(backup, target)
        raise
    return {'status': 'APPLIED', 'backup': str(backup_root)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-dir', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    package_dir = Path(__file__).resolve().parent.parent
    plan = prepare_plan(args.module_dir, package_dir)
    plan['dry_run'] = not args.apply
    if args.apply:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = PROJECT_ROOT / '_e5_v2_source_backups' / timestamp
        plan.update(apply(plan, backup))
    print(json.dumps(plan, indent=2))

if __name__ == '__main__':
    main()
