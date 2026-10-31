#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Public release installation with exact tags, asset hashes and native OS checks."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

class Unavailable(RuntimeError):
    pass

class MissingAsset(Unavailable):
    def __init__(self, metadata, name, target, asset_name):
        self.product = name
        self.target = target
        super().__init__(metadata.get("tag_name", "")+" has no native "+asset_name+" release asset")

def native_platform():
    system = {'Linux': 'linux', 'Darwin': 'macos', 'Windows': 'windows'}[platform.system()]
    machine = platform.machine().lower()
    arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine)
    if not arch:
        raise Unavailable('unsupported native architecture: '+machine)
    return system+'-'+arch

def read_url(url):
    headers = {'User-Agent': 'lmdebug-public-integration'}
    if url.startswith('https://api.github.com/'):
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if token:
            headers['Authorization'] = 'Bearer '+token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()

def release(repo, tag):
    return json.loads(read_url('https://api.github.com/repos/'+repo+'/releases/tags/'+tag))

def select_asset(metadata, name, target):
    suffix = '.exe' if target.startswith('windows-') else ''
    asset_name = name+'-'+target+suffix
    if name == 'lmconn':
        asset_name = name+'-'+target.replace('macos-', 'darwin-')+'.tar.gz'
    matches = [a for a in metadata['assets'] if a['name'] == asset_name]
    if not matches:
        raise MissingAsset(metadata, name, target, asset_name)
    if len(matches) != 1:
        raise Unavailable('ambiguous release asset: '+asset_name)
    return matches[0]

def expected_digest(metadata, asset):
    digest = asset.get('digest') or ''
    if digest.startswith('sha256:'):
        return digest.split(':', 1)[1]
    checksum = next((a for a in metadata['assets'] if a['name'] in ('SHA256SUMS', 'SHA256SUMS.txt')), None)
    if not checksum:
        raise Unavailable('release has no SHA-256 proof for '+asset['name'])
    for line in read_url(checksum['browser_download_url']).decode('utf-8').splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip('./*') == asset['name']:
            return fields[0]
    raise Unavailable('checksum does not cover '+asset['name'])

def verify(data, digest):
    if len(digest) != 64 or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('release asset SHA-256 mismatch')

def executable_bytes(data, asset_name, name, target):
    if not asset_name.endswith('.tar.gz'):
        return data
    wanted = name+('.exe' if target.startswith('windows-') else '')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        candidates = {wanted, asset_name.removesuffix('.tar.gz'), name+'-'+target+('.exe' if target.startswith('windows-') else '')}
        matches = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name in candidates]
        if len(matches) != 1:
            raise ValueError('archive must contain exactly one '+wanted)
        return archive.extractfile(matches[0]).read()

def install(name, spec, target, directory):
    metadata = release(spec['repo'], spec['tag'])
    asset = select_asset(metadata, name, target)
    digest = expected_digest(metadata, asset)
    data = read_url(asset['browser_download_url'])
    verify(data, digest)
    binary = directory/(name+('.exe' if target.startswith('windows-') else ''))
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(executable_bytes(data, asset['name'], name, target))
    binary.chmod(0o755)
    return binary, {'repo': spec['repo'], 'tag': spec['tag'], 'asset': asset['name'],
                    'asset_sha256': digest, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}

def command(executable, *args):
    executable = str(executable)
    if os.name == 'nt' and Path(executable).suffix.lower() in ('.cmd', '.bat'):
        return ['cmd.exe', '/d', '/c', executable, *map(str, args)]
    return [executable, *map(str, args)]

def install_mock(compiler, spec, target, directory, work, env):
    """Use the real lmscript install= path, then independently verify its PE/ELF."""
    metadata = release(spec['repo'], spec['tag'])
    asset = select_asset(metadata, 'lmmock', target)
    digest = expected_digest(metadata, asset)
    result = subprocess.run(command(compiler, 'install', 'github:'+spec['repo']+'@'+spec['tag']), env=env, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('lmscript lmmock install failed: '+result.stdout+result.stderr)
    lines = [line[len('path: '):] for line in result.stdout.splitlines() if line.startswith('path: ')]
    if len(lines) != 1:
        raise RuntimeError('lmmock installer did not identify its executable')
    selected = Path(lines[0]).resolve(strict=True)
    data = selected.read_bytes()
    verify(data, digest)
    binary = directory/('lmmock.exe' if target.startswith('windows-') else 'lmmock')
    shutil.copy2(selected, binary); binary.chmod(0o755)
    return binary, {'repo': spec['repo'], 'tag': spec['tag'], 'asset': asset['name'],
                    'binary_sha256': digest, 'installation': 'lmscript install=github:'+spec['repo']+'@'+spec['tag']}
