#!/usr/bin/env python3

from getpass import getpass
import argparse
import configparser
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

def get_aes_key(access_token, path):
    data = request('GET', '/organizations/{}/projects?per_page=50'.format(PCULTURE_UUID),
                   access_token)
    key_map = {
        repo_name_from_url(data['repository_url']): data['aes_key']
        for data in data['projects']
    }
    return key_map[repo_name_from_path(path)]

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

def update_secret_data(data, name):
    data = data.decode('utf8')
    value = input('new value for {}: '.format(name))
    lines = data.split('\n')
    for i in range(len(lines)):
        if lines[i].startswith('{}='.format(name)):
            lines[i] = '{}={}'.format(name, value)
            break
    else:
        print("{} not currently in the data".format(name))

    return ('\n'.join(lines)).encode('utf8')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='path of the credentials file')
    parser.add_argument('name', help='name of the credential to update')
    return parser.parse_args()

def main():
    args = parse_args()
    path = os.path.abspath(args.path)

    access_token = login()

    aes_key = get_aes_key(access_token, path)
    secret_data = decrypt(path, aes_key)
    secret_data = tupdate_secret_data(secret_data, args.name)
    encrypt(path, aes_key, secret_data)
    print('{} updated for {}'.format(args.name, args.path))

if __name__ == '__main__':
    main()
