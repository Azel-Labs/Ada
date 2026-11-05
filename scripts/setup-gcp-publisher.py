#!/usr/bin/env python3
"""Authorize this proxy repository to use the existing Ada image publisher in Cloud Shell."""
import argparse
import json
import re
import subprocess
from urllib.request import urlopen


def run(*args):
    subprocess.run(args, check=True)


def data(*args):
    return json.loads(subprocess.check_output(args))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default='Azel-Labs/Ada')
    parser.add_argument('--project', default='cypherpunklabs')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('invalid owner/repository')
    with urlopen('https://api.github.com/repos/' + args.repository, timeout=30) as response:
        repo = json.load(response)
    project = data('gcloud', 'projects', 'describe', args.project, '--format=json')
    account = 'ada-image-publisher@' + args.project + '.iam.gserviceaccount.com'
    pool, provider = 'ada-image-publisher', 'ada-proxy'
    # Reuse the existing bucket, publisher role and service account. Do not create
    # broad IAM grants or modify the OS repository's federation provider.
    providers = data('gcloud', 'iam', 'workload-identity-pools', 'providers', 'list',
                     '--project=' + args.project, '--location=global',
                     '--workload-identity-pool=' + pool, '--format=json')
    operation = 'update-oidc' if any(p['name'].endswith('/' + provider) for p in providers) else 'create-oidc'
    condition = (f"assertion.repository_id == '{repo['id']}' && "
                 f"assertion.repository_owner_id == '{repo['owner']['id']}' && "
                 "assertion.ref == 'refs/heads/main' && "
                 f"assertion.workflow_ref == '{args.repository}/.github/workflows/ci.yml@refs/heads/main'")
    run('gcloud', 'iam', 'workload-identity-pools', 'providers', operation, provider,
        '--project=' + args.project, '--location=global', '--workload-identity-pool=' + pool,
        '--issuer-uri=https://token.actions.githubusercontent.com',
        '--attribute-mapping=google.subject=assertion.sub,attribute.repository_id=assertion.repository_id',
        '--attribute-condition=' + condition)
    principal = (f'principalSet://iam.googleapis.com/projects/{project["projectNumber"]}/locations/global/'
                 f'workloadIdentityPools/{pool}/attribute.repository_id/{repo["id"]}')
    run('gcloud', 'iam', 'service-accounts', 'add-iam-policy-binding', account,
        '--project=' + args.project, '--role=roles/iam.workloadIdentityUser',
        '--member=' + principal, '--condition=None')
    print('Authorized ' + args.repository + '/.github/workflows/ci.yml on main.')
    print('GCP_WORKLOAD_IDENTITY_PROVIDER=' +
          f'projects/{project["projectNumber"]}/locations/global/workloadIdentityPools/{pool}/providers/{provider}')


if __name__ == '__main__':
    main()
