#!/usr/bin/env python3

from getpass import getpass
import argparse
import os
import re
import subprocess

import requests
from requests.auth import HTTPBasicAuth


API_BASE_URL = 'https://api.codeship.com/v2'
PCULTURE_UUID = '654a92f0-9240-0135-7b6e-1a64a5dfad49'

REPO_PATTERNS = [
    'git@github.com:pculture/(.*)',
    'https://github.com/pculture/(.*)',
]
REPO_PATTERNS = [re.compile(r) for r in REPO_PATTERNS]

class APIError(Exception):
    def __init__(self, response):
        self.status_code = response.status_code
        self.text = response.text

    def __str__(self):
        return 'APIError {}: {}'.format(self.status_code, self.text)

def request(method, endpoint, access_token, data=None, **kwargs):
    assert endpoint.startswith('/')
    kwargs = kwargs.copy()
    if access_token:
        kwargs['headers'] = {
            'Authorization': access_token
        }
    if data:
        kwargs['json'] = data

    response = requests.request(method, API_BASE_URL + endpoint, **kwargs)
    if response.status_code != 200:
        raise APIError(response)
    return response.json()

def login():
    username = input('codeship email: ')
    password = getpass('codeship password: ')
    data = request('POST', '/auth', None, {},
                   auth=HTTPBasicAuth(username, password))
    return data['access_token']

def get_aes_keys(access_token, source, dest):
    data = request('GET', '/organizations/{}/projects?per_page=50'.format(PCULTURE_UUID),
                   access_token)
    key_map = {
        repo_name_from_url(data['repository_url']): data['aes_key']
        for data in data['projects']
    }
    source_key = key_map[repo_name_from_path(source)]
    dest_key = key_map[repo_name_from_path(dest)]
    return source_key, dest_key

def repo_name_from_url(url):
    for regex in REPO_PATTERNS:
        m = regex.match(url)
        if m:
            name = m.group(1)
            if name.endswith('.git'):
                name = name[:-4]
            return name
    raise ValueError("Unknown repo URL: {}".format(url))

def repo_name_from_path(path):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        path = os.path.dirname(path)
    result = subprocess.run(['git', 'config', '--get', 'remote.origin.url'],
                            cwd=path, stdout=subprocess.PIPE)
    return repo_name_from_url(result.stdout.decode('utf8').strip())

def decrypt(path, key):
    cmdline = [
        'jet', 'decrypt', path, '/dev/stdout', '--key-path', '/dev/stdin',
    ]
    result = subprocess.run(cmdline, input=key.encode('utf8'), stdout=subprocess.PIPE)
    return result.stdout

def encrypt(path, key, data):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, data)
    os.close(write_fd)
    cmdline = [
        'jet', 'encrypt', '/proc/self/fd/{}'.format(read_fd), path,
        '--key-path', '/dev/stdin',
    ]
    subprocess.run(cmdline, input=key.encode('utf8'), pass_fds=[read_fd])

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', help='encrypted creds source path')
    parser.add_argument('dest', help='encrypted creds dest path')
    return parser.parse_args()

def main():
    args = parse_args()
    source = os.path.abspath(args.source)
    dest = os.path.abspath(args.dest)
    if os.path.isdir(dest):
        dest = os.path.join(dest, os.path.basename(source))

    access_token = login()

    source_key, dest_key = get_aes_keys(access_token, source, dest)
    secret_data = decrypt(source, source_key)
    encrypt(dest, dest_key, secret_data)
    print('credentials copied from {} to {}'.format(
        source, dest))

if __name__ == '__main__':
    main()
