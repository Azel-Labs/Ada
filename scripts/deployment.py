#!/usr/bin/env python3
"""Select an authenticated OS release and bind this repository's proxy to its boot image."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OS_REPOSITORY = 'Azel-Labs/Ada-image'
PROFILE = 'gcp-tdx-platform-profile.json'
PROOFS = ('release.json', 'image-release.json', 'release.sigstore.json')
DEPLOYMENT_FILES = ('deployment-gcp.tar.gz', 'deployment.efi', 'cmdline', 'workload.tar',
                    'workload-disk.tar.gz', 'os-release.json', 'os-release.sigstore.json', PROFILE)
sys.path.insert(0, str(ROOT / 'deployment'))
from release_proof import load_release_proof


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def selected_version(root=ROOT):
    value = (root / 'image-version').read_text().strip()
    require(re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?', value),
            'image-version must select an explicit OS release, such as v0.1.0')
    return value


def verify_os(directory, version, check_files=True):
    manifest = json.loads((directory / 'os-release.json').read_text())
    require(manifest.get('kind') == 'ada-image.os-release.v1' and manifest['tag'] == version
            and manifest['source_repository'] == OS_REPOSITORY
            and manifest['source_ref'] == 'refs/tags/' + version
            and manifest['build_workflow'] == '.github/workflows/image.yml', 'OS release identity mismatch')
    commit = manifest['source_commit']
    require(re.fullmatch('[0-9a-f]{40}', commit) and manifest['workflow_commit'] == commit,
            'OS workflow must match the tagged source')
    # Authenticate before executing anything from the downloaded tool archive.
    run('gh', 'attestation', 'verify', directory / 'os-release.json',
        '--bundle', directory / 'os-release.sigstore.json', '--repo', OS_REPOSITORY,
        '--signer-workflow', OS_REPOSITORY + '/.github/workflows/image.yml',
        '--signer-digest', commit, '--source-digest', commit, '--source-ref', 'refs/tags/' + version,
        '--predicate-type', 'https://slsa.dev/provenance/v1', '--deny-self-hosted-runners')
    if check_files:
        require({'image-tools.tar.gz', 'ada-image-gcp.tar.gz', PROFILE} <= set(manifest['files']),
                'OS release lacks assembly tools, disk or qualified platform profile')
        for name, entry in manifest['files'].items():
            require(Path(name).name == name and name not in ('.', '..'), 'unsafe OS artifact name')
            path = directory / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == entry['size']
                    and digest(path) == entry['sha256'], 'OS artifact mismatch: ' + name)
    return manifest


def unpack_tools(archive_path, destination):
    require(not destination.exists(), 'OS tools destination must be fresh')
    with tarfile.open(archive_path, 'r:gz') as archive:
        names = set()
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and str(name) not in ('', '.')
                    and str(name) not in names and (member.isfile() or member.isdir()), 'unsafe OS tools archive')
            names.add(str(name))
        archive.extractall(destination, filter='data')
    require((destination / 'scripts/assemble-release').is_file(), 'OS assembly tool missing')


def select_os(base, tools, root=ROOT):
    version = selected_version(root)
    require(not base.exists(), 'OS download directory must be fresh')
    base.mkdir(parents=True)
    run('gh', 'release', 'download', version, '--repo', OS_REPOSITORY, '--dir', base)
    verify_os(base, version)
    unpack_tools(base / 'image-tools.tar.gz', tools)


def build_workload(directory, staging, root=ROOT):
    lock = json.loads((directory / 'images.lock.json').read_text())
    require(lock['schema'] == 1 and set(lock['services']) == {'ada-proxy'}, 'only the proxy may be packaged')
    proxy = lock['services']['ada-proxy']
    reference = proxy['image'] + '@' + proxy['digest']
    require(re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}', reference),
            'proxy must be selected by OCI digest')
    staging.mkdir(parents=True, exist_ok=False)
    run('docker', 'pull', '--platform=linux/amd64', reference)
    config = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference]))[0]
    require(config['Architecture'] == 'amd64' and config['Os'] == 'linux'
            and reference in config.get('RepoDigests', [])
            and re.fullmatch(r'sha256:[0-9a-f]{64}', config['Id']), 'pulled proxy identity/platform mismatch')
    # Export the verified config ID; the guest loads this exact ID without tags.
    run('docker', 'save', '--output', staging / 'proxy.tar', config['Id'])
    (staging / 'proxy-image-id').write_text(config['Id'] + '\n')
    compose = json.loads((root / 'deployment/compose.json').read_text())
    require(set(compose['services']) == {'ada-proxy'}, 'deployment must contain only the proxy')
    service = compose['services']['ada-proxy']
    service['image'] = reference
    service['pull_policy'] = 'never'
    service['environment'].update(ADA_SOURCE_REPOSITORY='https://github.com/' + proxy['source_repository'],
                                  ADA_SOURCE_COMMIT=proxy['source_commit'], ADA_IMAGE_DIGEST=proxy['digest'])
    # JSON is a YAML subset accepted by Compose; exact serialized bytes are measured.
    write_json(staging / 'compose.yaml', compose)
    shutil.copyfile(directory / 'images.lock.json', staging / 'images.lock.json')
    for name in ('start', 'launch.py', 'release_proof.py'):
        shutil.copyfile(root / 'deployment' / name, staging / name)
    release = {'schema': 1, 'profile': 'ada.gcp-tdx.v1', 'tag': proxy['release_tag'],
               'source_commit': proxy['source_commit'], 'os_repository': OS_REPOSITORY,
               'os_version': selected_version(root), 'compose_sha256': digest(staging / 'compose.yaml'),
               'image_lock_sha256': digest(staging / 'images.lock.json'), 'containers': {'ada-proxy': reference}}
    write_json(staging / 'release.json', release)
    write_json(staging / 'assets.json', {p.name: digest(p) for p in sorted(staging.iterdir())})
    # Explicit staging allowlist above: never archive the checkout, .env or config disk.
    with tarfile.open(directory / 'workload.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(staging.iterdir()):
            info = archive.gettarinfo(path, arcname=path.name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = 'root'
            info.mode = 0o755 if path.name == 'start' else 0o644
            with path.open('rb') as stream:
                archive.addfile(info, stream)
    for name in ('release.json', 'compose.yaml'):
        shutil.copyfile(staging / name, directory / name)


def finalize(directory, version):
    deployment = json.loads((directory / 'deployment.json').read_text())
    release_bytes = (directory / 'release.json').read_bytes()
    release = json.loads(release_bytes)
    require(deployment['os']['tag'] == version and release['os_version'] == version, 'selected OS changed')
    event = hashlib.sha384(b'ada.release.v1\0' + release_bytes).digest()
    rtmr3 = hashlib.sha384(bytes(48) + event).hexdigest()
    appraisal = deployment['platform_appraisal']
    require(appraisal['status'] == 'included', 'qualified GCP boot measurements required')
    expected = dict(appraisal['expected_boot'], rtmr3=rtmr3)
    image = {'schema': 1, 'profile': 'ada.gcp-tdx.boot.v1', 'source_commit': release['source_commit'],
             'workload_release_sha256': hashlib.sha256(release_bytes).hexdigest(),
             'workload_sha256': deployment['workload_sha256'], 'application_rtmr3': rtmr3,
             'boot': deployment['boot'], 'expected_measurements': expected,
             'deployment': deployment,
             # Preserve the exact signed OS bytes for recipients of /v1/attestation.
             'os_release_manifest': (directory / 'os-release.json').read_text(),
             'os_release_sigstore_bundle': (directory / 'os-release.sigstore.json').read_text(),
             'embedded_application_credentials': False,
             'runtime_configuration': {'filesystem_label': 'ada-config', 'env_file': '/mnt/config/secrets.env',
                                       'release_proof_directory': '/mnt/config/release-proof'}}
    write_json(directory / 'image-release.json', image)
    with (directory / 'release-notes.md').open('a') as output:
        output.write(f'\nOS: `{OS_REPOSITORY}@{version}`. Workload SHA-256: `{deployment["workload_sha256"]}`.\n\n'
                     'Deploy the boot image and the separate `ada-workload` disk from this release together. '
                     'Attach a private `ada-config` disk containing `secrets.env` and the `release-proof/` '
                     'directory from `release-proof.tar.gz`. TLS terminates in the proxy on VM port 443.\n\n'
                     'Required GCP machine and firmware configuration: `deployment.json` → '
                     '`platform_appraisal.launch`. Live TDX boot verification is separate from image assembly.\n')


def three_disk_events(profile):
    """Derive GCP's boot variables for boot/workload/config NVMe namespaces.

    The firmware, ACPI and security variables remain the signed OS references.
    EFI_LOAD_OPTION and BootOrder values are encoded explicitly; no live quote
    or server-supplied digest selects the expected result. The single-disk
    BootOrder and Boot0001 encodings must reproduce the authenticated baseline.
    """
    reference = profile['rtmr0_events']
    require(profile['launch']['machine_type'] == 'c3-standard-4'
            and profile['launch']['reference_disk_count'] == 1
            and profile['launch']['boot_disk_interface'] == 'NVME'
            and len(reference) == 14, 'unsupported GCP baseline layout')
    def variable(name, data):
        # EV_EFI_VARIABLE_BOOT measures VariableData, not the surrounding
        # EFI_VARIABLE_DATA event record (GUID, lengths and variable name).
        return {'type': 0x80000002, 'description': name + ' variable',
                'sha384': hashlib.sha384(data).hexdigest()}

    def nvme(number):
        description = 'UEFI nvme_card-pd' + ('' if number == 1 else ' ' + str(number))
        # ACPI PciRoot(0), PCI(4,0), NVMe(namespace, EUI64=0), End.
        device_path = (bytes.fromhex('02010c00d041030a0000000001010600000403171000')
                       + struct.pack('<IQ', number, 0) + bytes.fromhex('7fff0400'))
        # Google's existing qualified boot option includes this vendor marker.
        optional = bytes.fromhex('4eac0881119f594d850ee21a522c59b2')
        value = (struct.pack('<IH', 1, len(device_path))
                 + (description + '\0').encode('utf-16le') + device_path + optional)
        return variable(f'Boot{number:04X}', value)

    baseline_order = variable('BootOrder', struct.pack('<HH', 1, 0))
    baseline_nvme = nvme(1)
    require(reference[11]['type'] == reference[12]['type'] == reference[13]['type'] == 0x80000002
            and reference[11]['sha384'] == baseline_order['sha384']
            and reference[12]['sha384'] == baseline_nvme['sha384']
            and reference[13]['description'] == 'Boot0000 UI application option',
            'GCP boot-option encoding differs from the qualified OS firmware')
    events = reference[:11] + [variable('BootOrder', struct.pack('<HHHH', 1, 2, 3, 0)),
                               reference[12], nvme(2), nvme(3), reference[13]]
    register = bytes(48)
    for event in events:
        register = hashlib.sha384(register + bytes.fromhex(event['sha384'])).digest()
    return events, register.hex()


def bind_deployment_platform(directory):
    profile = json.loads((directory / PROFILE).read_text())
    events, rtmr0 = three_disk_events(profile)
    deployment = json.loads((directory / 'deployment.json').read_text())
    appraisal = deployment['platform_appraisal']
    require(appraisal['profile_sha256'] == digest(directory / PROFILE)
            and appraisal['expected_boot']['rtmr0'] == profile['rtmr0'], 'base platform appraisal mismatch')
    appraisal['base_rtmr0'] = profile['rtmr0']
    appraisal['deployment_rtmr0_events'] = events
    appraisal['expected_boot']['rtmr0'] = rtmr0
    appraisal['launch'].update(disk_count=3, disk_interfaces=['NVME', 'NVME', 'NVME'],
                               boot_order=[1, 2, 3, 0])
    appraisal['scope'] = ('GCP c3-standard-4 with boot, workload and configuration NVMe disks in that order. '
                          'Firmware/security/ACPI references come from the signed OS profile; '
                          'BootOrder and added namespace boot options are calculated from this layout.')
    write_json(directory / 'deployment.json', deployment)


def assemble(directory, base, tools, output, root=ROOT):
    version = selected_version(root)
    run('nix', 'develop', 'path:' + str(tools.resolve()), '--command', 'python3',
        tools / 'scripts/assemble-release', '--os-directory', base, '--os-repository', OS_REPOSITORY,
        '--os-version', version, '--workload', directory / 'workload.tar', '--output', output)
    for name in (*DEPLOYMENT_FILES, 'deployment.json'):
        if name != 'workload.tar':
            shutil.copyfile(output / name, directory / name)
    require(digest(directory / 'workload.tar') == digest(output / 'workload.tar'), 'assembler changed workload')
    bind_deployment_platform(directory)
    finalize(directory, version)


def package_proof(directory):
    files = load_release_proof(directory)
    with tarfile.open(directory / 'release-proof.tar.gz', 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo('release-proof/' + name)
            info.size, info.mode, info.mtime = len(raw), 0o444, 0
            archive.addfile(info, io.BytesIO(raw))


def verify_deployment(directory, entry):
    """Check the complete signed hash chain before any release publication."""
    proofs = load_release_proof(directory)
    release = json.loads(proofs['release.json'])
    image = json.loads(proofs['image-release.json'])
    deployment = json.loads((directory / 'deployment.json').read_text())
    require(release['source_commit'] == entry['source_commit'] and release['tag'] == entry['release_tag']
            and release['containers'] == {'ada-proxy': entry['image'] + '@' + entry['digest']}, 'workload identity mismatch')
    require(release['compose_sha256'] == digest(directory / 'compose.yaml')
            and release['image_lock_sha256'] == digest(directory / 'images.lock.json'), 'workload metadata mismatch')
    require(deployment['kind'] == 'ada-image.deployment.v1' and image['deployment'] == deployment
            and set(deployment['files']) == set(DEPLOYMENT_FILES), 'deployment manifest mismatch')
    for name, expected in deployment['files'].items():
        require(digest(directory / name) == expected, 'deployment artifact mismatch: ' + name)
    require(image['workload_sha256'] == deployment['workload_sha256'] == digest(directory / 'workload.tar'),
            'workload archive mismatch')
    with tarfile.open(directory / 'workload.tar', 'r:') as archive:
        for name in ('release.json', 'compose.yaml', 'images.lock.json'):
            members = [member for member in archive.getmembers() if member.name == name]
            require(len(members) == 1 and members[0].isfile()
                    and members[0].size == (directory / name).stat().st_size
                    and archive.extractfile(members[0]).read() == (directory / name).read_bytes(),
                    'measured workload differs from published metadata: ' + name)
    require(image['boot'] == deployment['boot'] and
            ('ada-image.workload_sha256=' + image['workload_sha256']) in image['boot']['kernel_command_line'].split(),
            'boot command line does not bind this workload')
    require(image['os_release_manifest'] == (directory / 'os-release.json').read_text()
            and image['os_release_sigstore_bundle'] == (directory / 'os-release.sigstore.json').read_text(),
            'OS proof differs from the attestation response')
    version = release['os_version']
    base = verify_os(directory, version, check_files=False)
    require(deployment['os'] == {'repository': OS_REPOSITORY, 'tag': version,
                                'source_commit': base['source_commit'],
                                'manifest_sha256': digest(directory / 'os-release.json')}, 'OS selection mismatch')
    appraisal = deployment['platform_appraisal']
    if appraisal['launch'].get('disk_count') == 3:
        events, rtmr0 = three_disk_events(json.loads((directory / PROFILE).read_text()))
        require(appraisal['deployment_rtmr0_events'] == events
                and appraisal['expected_boot']['rtmr0'] == rtmr0, 'deployment disk measurements mismatch')
    require(appraisal['status'] == 'included'
            and digest(directory / PROFILE) == base['files'][PROFILE]['sha256'] == appraisal['profile_sha256']
            and image['expected_measurements'] == dict(appraisal['expected_boot'], rtmr3=image['application_rtmr3']),
            'deployment measurement policy mismatch')
    with tarfile.open(directory / 'release-proof.tar.gz', 'r:gz') as archive:
        require(archive.getnames() == ['release-proof/' + name for name in PROOFS], 'unexpected public proof files')
        for member, name in zip(archive.getmembers(), PROOFS):
            require(member.isfile() and archive.extractfile(member).read() == proofs[name], 'public proof archive mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['select', 'workload', 'assemble', 'proof'])
    parser.add_argument('--directory', type=Path, default=ROOT / 'dist')
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    directory = args.directory.resolve()
    if args.command == 'select':
        select_os(work / 'os', work / 'tools')
    elif args.command == 'workload':
        build_workload(directory, work / 'workload')
    elif args.command == 'assemble':
        assemble(directory, work / 'os', work / 'tools', work / 'assembled')
    else:
        package_proof(directory)


if __name__ == '__main__':
    main()
