#!/usr/bin/env python3
"""Build a signed catalogue from explicitly approved, checksum-pinned releases."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
KEY_ID = 'cartridge-official-v1'
MAX_PACKAGE = 32 * 1024 * 1024
ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z')
VERSION = re.compile(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\Z')

def download(url):
    if not url.startswith('https://github.com/'):
        raise ValueError('Only reviewed GitHub release packages are supported')
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'CartridgeOS-Catalog/1'}), timeout=60) as response:
        if response.status != 200 or not response.url.startswith('https://'):
            raise ValueError('Package download failed or redirected outside HTTPS')
        data = response.read(MAX_PACKAGE + 1)
    if len(data) > MAX_PACKAGE:
        raise ValueError('Package exceeds 32 MiB')
    return data

def inspect_package(data, approved):
    if len(data) != approved['size'] or hashlib.sha256(data).hexdigest() != approved['sha256']:
        raise ValueError('Package differs from the approved checksum/size')
    files = set()
    total = 0
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or '\\' in member.name or member.name in files:
                raise ValueError('Unsafe or duplicate archive path')
            if not (member.isfile() or member.isdir()):
                raise ValueError('Archive links and special files are forbidden')
            files.add(member.name)
            total += member.size
            if len(files) > 4096 or total > 128 * 1024 * 1024:
                raise ValueError('Expanded package is too large')
            if member.name == 'cartridge.json':
                if member.size > 65536:
                    raise ValueError('Manifest is too large')
                manifest = json.load(archive.extractfile(member))
    if not manifest or manifest['id'] != approved['id'] or manifest['version'] != approved['version']:
        raise ValueError('Release identity/version does not match its approval')
    if manifest.get('entry') != 'main.lua' or 'main.lua' not in files:
        raise ValueError('Release must contain main.lua at its root')
    if not VERSION.fullmatch(manifest.get('min_runtime','')):
        raise ValueError('Release must declare min_runtime')
    permissions = manifest.get('permissions', [])
    if sorted(permissions) != sorted(approved['permissions']):
        raise ValueError('Permissions changed; review and approve them explicitly')
    allowed = {'network','audio','storage','ssh','system'}
    if not set(permissions) <= allowed or len(permissions) != len(set(permissions)):
        raise ValueError('Unknown or duplicate permissions')
    return manifest

def build(index, fetch=download):
    ids = set()
    apps = []
    if index.get('version') != 1:
        raise ValueError('Unknown approval index version')
    for approved in index['apps']:
        app_id, version, repo = (approved[k] for k in ('id','version','repo'))
        if not ID.fullmatch(app_id) or app_id in ids or not VERSION.fullmatch(version):
            raise ValueError('Invalid/duplicate app ID or version')
        if not re.fullmatch(r'Strizzo/[A-Za-z0-9._-]+', repo):
            raise ValueError('Official apps must use reviewed Strizzo repositories')
        if not re.fullmatch('[a-f0-9]{64}', approved['sha256']) or not 0 < approved['size'] <= MAX_PACKAGE:
            raise ValueError('Invalid approved checksum or size')
        ids.add(app_id)
        url = f'https://github.com/{repo}/releases/download/v{version}/{app_id}.tar.gz'
        manifest = inspect_package(fetch(url), approved)
        app = {key: manifest[key] for key in ('id','name','description','version','author','category','permissions')}
        app['tags'] = manifest.get('tags', [])
        app['repo_url'] = f'https://github.com/{repo}'
        app['package'] = {'url':url,'sha256':approved['sha256'],'size':approved['size'],'min_runtime':manifest['min_runtime']}
        apps.append(app)
    return {'version':2,'apps':sorted(apps,key=lambda a:a['id'])}

def openssl(*args):
    subprocess.run([os.environ.get('OPENSSL','openssl'), *map(str,args)], check=True, capture_output=True)

def sign(catalog, key_path):
    payload = json.dumps(catalog, separators=(',',':'), ensure_ascii=False)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp/'payload').write_bytes(payload.encode())
        openssl('pkeyutl','-sign','-rawin','-inkey',key_path,'-in',tmp/'payload','-out',tmp/'signature')
        signature = (tmp/'signature').read_bytes().hex()
    return {'key_id':KEY_ID,'payload':payload,'signature':signature}

def verify(envelope, public_key):
    if envelope['key_id'] != KEY_ID:
        raise ValueError('Unknown signing key')
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp/'payload').write_bytes(envelope['payload'].encode())
        (tmp/'signature').write_bytes(bytes.fromhex(envelope['signature']))
        openssl('pkeyutl','-verify','-rawin','-pubin','-inkey',public_key,'-in',tmp/'payload','-sigfile',tmp/'signature')
    return json.loads(envelope['payload'])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sign-key',type=Path)
    parser.add_argument('--verify',action='store_true')
    args = parser.parse_args()
    if args.verify:
        envelope = json.loads((ROOT/'catalog.json').read_text())
        published = verify(envelope, ROOT/'keys'/f'{KEY_ID}.pem')
        expected = build(json.loads((ROOT/'apps.json').read_text()))
        if published != expected:
            raise ValueError('Published catalogue does not match approved releases')
        print(f'Verified signed catalogue and {len(published["apps"])} release packages')
        return
    catalog = build(json.loads((ROOT/'apps.json').read_text()))
    if not args.sign_key:
        print(f'Validated {len(catalog["apps"])} approved release packages (not published)')
        return
    envelope = sign(catalog, args.sign_key)
    verify(envelope, ROOT/'keys'/f'{KEY_ID}.pem')
    (ROOT/'catalog.json').write_text(json.dumps(envelope,indent=2,ensure_ascii=False)+'\n')
    print(f'Signed {len(catalog["apps"])} approved releases')

if __name__ == '__main__':
    main()
