#!/usr/bin/env python3
import sys
from fsocks.log import logger


def check_python():
    info = sys.version_info
    if info[0] < 3 or info[1] < 5:
        print('Python 3.5+ required')
        sys.exit(1)


class Config:

    def __init__(self):
        self.raw = {
            "client_host": "127.0.0.1",
            "client_port": 1080,
            "server_host": "0.0.0.0",
            "server_port": 1081,
            "method": "sha256",
            "password": "my_password",
            "timeout": 6.6,
            "loglevel": "DEBUG"
        }

    @property
    def client_address(self):
        return (self.client_host, self.client_port)

    @property
    def server_address(self):
        return (self.server_host, self.server_port)

    def load_args(self):
        import json
        import argparse
        parser = argparse.ArgumentParser(
            description='Yet another tunnel proxy')
        parser.add_argument('-c', '--config', required=True,
                            help='path to config file')
        check_python()
        args = parser.parse_args()
        print('Loading config {}'.format(args.config))
        with open(args.config) as f:
            _cfg = json.load(f)
        self.raw.update(_cfg)
        for key in self.raw:
            setattr(self, key, self.raw[key])
        logger.setLevel(self.loglevel)


config = Config()
