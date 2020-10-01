#!/usr/bin/env python3

from getpass import getpass
import argparse
import contextlib
import logging
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

class CodeshipCryto:
    def __init__(self):
        access_token = login()

        logging.debug('fetching AES keys')
        data = request('GET', '/organizations/{}/projects?per_page=50'.format(PCULTURE_UUID),
                       access_token)
        self.aes_key_map = {
            repo_name_from_url(data['repository_url']): data['aes_key']
            for data in data['projects']
        }

    def get_key(self, path):
        return self.aes_key_map[repo_name_from_path(path)]

    def decrypt(self, path):
        key = self.get_key(path)
        with jet_data_file(key) as keyfile:
            cmdline = [
                'jet', 'decrypt', path, '/dev/stdout', '--key-path', keyfile,
            ]
            result = subprocess.run(cmdline, stdout=subprocess.PIPE,
                                    encoding='utf8')
            return result.stdout

    def encrypt(self, path, data):
        key = self.get_key(path)
        with jet_data_file(key) as keyfile:
            with jet_data_file(data) as datafile:
                cmdline = [
                    'jet', 'encrypt', datafile, path, '--key-path', keyfile,
                ]
                subprocess.run(cmdline)

# Create a class for each subcommand
class Subcommand:
    def name(self):
        return self.__class__.__name__.lower()

    def add_to_subparsers(self, subparsers):
        parser = subparsers.add_parser(self.name())
        parser.set_defaults(subcommand=self)
        # Verbose is standard for all commands
        parser.add_argument('-v', '--verbose', action='store_true')
        self.add_arguments(parser)

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

        crypto = CodeshipCryto()
        logging.debug(f'decrypting credentials from {source}')
        secret_data = crypto.decrypt(source)
        logging.debug(f'encrypting credentials to {dest}')
        crypto.encrypt(dest, secret_data)
        logging.info('credentials copied from {} to {}'.format(
            source, dest))

class Print(Subcommand):
    def add_arguments(self, parser):
        parser.add_argument('path', help='encrypted creds path', nargs='+')
        parser.add_argument('-n', '--name_only', action='store_true')

    def run(self, args):
        crypto = CodeshipCryto()
        all_secret_data = []
        for source in args.path:
            source = os.path.abspath(source)
            logging.debug(f'decrypting credentials from {source}')
            secret_data = crypto.decrypt(source)
            if args.name_only:
                secret_data = '\n'.join(
                    line.split('=')[0] for line in secret_data.split('\n')
                )
            all_secret_data.append(secret_data)


        if len(all_secret_data) == 1:
            # 1 file, just print the secrets
            print()
            print(secret_data)
        else:
            # Multiple files, print the filename, then secrets
            for (source, secret_data) in zip(args.path, all_secret_data):
                print()
                print(source)
                print(secret_data)

def create_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    for SubCommandClass in Subcommand.__subclasses__():
        subcommand = SubCommandClass()
        subcommand.add_to_subparsers(subparsers)
    return parser

def setup_logging(args):
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format='{levelname} {message}',
        style='{')
    # squash debugging from urllib
    logging.getLogger('urllib3').setLevel(logging.INFO)

def main():
    parser = create_parser()
    args = parser.parse_args()
    if hasattr(args, 'subcommand'):
        setup_logging(args)
        args.subcommand.run(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
