#!/usr/bin/env python3

from getpass import getpass
import argparse
import contextlib
import os
import re
import subprocess
import tempfile

import requests
from requests.auth import HTTPBasicAuth


API_BASE_URL = 'https://api.codeship.com/v2'
PCULTURE_UUID = '654a92f0-9240-0135-7b6e-1a64a5dfad49'

REPO_PATTERNS = [
    'git@github.com:pculture/(.*)',
    'https://github.com/pculture/(.*)',
]
REPO_PATTERNS = [re.compile(r) for r in REPO_PATTERNS]
# Map git repos to codeship project names, in case they don't match
REPO_NAME_MAP = {
    'pculture.org': 'pcf',
}

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
            return REPO_NAME_MAP.get(name, name)
    raise ValueError("Unknown repo URL: {}".format(url))

def repo_name_from_path(path):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        path = os.path.dirname(path)
    result = subprocess.run(['git', 'config', '--get', 'remote.origin.url'],
                            cwd=path, stdout=subprocess.PIPE)
    return repo_name_from_url(result.stdout.decode('utf8').strip())

@contextlib.contextmanager
def jet_data_file(data):
    """
    Create a file to pass to jet with specific data

    This is a context manager that creates a file that stores data and can be
    passed to the jet CLI.
    """
    # Best practice would be to pass the data through a pipe, to avoid any
    # chance that another process could access it.  However it doesn't seem
    # to work with jet (we get errors like "Your Project's AES key is missing,
    # please download from Project Settings")
    #
    # We use a NamedTemporaryFile instead, which should be fairly safe.  In
    # order to exploit this someone would need a program running on the dev's
    # machine continuously monitored the tempfiles and was able to read the
    # data before jet completes and we delete the file.
    with tempfile.NamedTemporaryFile(mode='w') as f:
        f.write(data)
        f.flush()
        yield f.name

def decrypt(path, key):
    with jet_data_file(key) as keyfile:
        cmdline = [
            'jet', 'decrypt', path, '/dev/stdout', '--key-path', keyfile,
        ]
        result = subprocess.run(cmdline, stdout=subprocess.PIPE,
                                encoding='utf8')
        return result.stdout

def encrypt(path, key, data):
    with jet_data_file(key) as keyfile:
        with jet_data_file(data) as datafile:
            cmdline = [
                'jet', 'encrypt', datafile, path, '--key-path', keyfile,
            ]
            subprocess.run(cmdline)

# Create a class for each subcommand
class Subcommand:
    ENABLE_VERBOSE = True

    def __init__(self):
        self.verbose = False

    def name(self):
        return self.__class__.__name__.lower()

    def add_to_subparsers(self, subparsers):
        parser = subparsers.add_parser(self.name())
        parser.set_defaults(subcommand=self)
        if self.ENABLE_VERBOSE:
            parser.add_argument('-v', '--verbose', action='store_true')
        self.add_arguments(parser)

    def setup(self, args):
        if self.ENABLE_VERBOSE and args.verbose:
            self.verbose = True

    def debug_log(self, text):
        if self.verbose:
            print(text)

    def add_arguments(self, parser):
        raise NotImplementedError()

    def run(self, args):
        raise NotImplementedError()

class Copy(Subcommand):
    def add_arguments(self, parser):
        parser.add_argument('source', help='encrypted creds source path')
        parser.add_argument('dest', help='encrypted creds dest path')

    def run(self, args):
        source = os.path.abspath(args.source)
        dest = os.path.abspath(args.dest)
        if os.path.isdir(dest):
            dest = os.path.join(dest, os.path.basename(source))

        access_token = login()

        self.debug_log('getting AES key')
        source_key, dest_key = get_aes_keys(access_token, source, dest)
        self.debug_log(f'decrypting credentials from {source}')
        secret_data = decrypt(source, source_key)
        self.debug_log(f'encrypting credentials to {dest}')
        encrypt(dest, dest_key, secret_data)
        print('credentials copied from {} to {}'.format(
            source, dest))

def create_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    for SubCommandClass in Subcommand.__subclasses__():
        subcommand = SubCommandClass()
        subcommand.add_to_subparsers(subparsers)
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    if hasattr(args, 'subcommand'):
        args.subcommand.setup(args)
        args.subcommand.run(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
