#!/usr/bin/env python3
import logging


formater = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formater)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


class Config:

    def __init__(self):
        self.raw = {
                "client_host": "127.0.0.1",
                "client_port": 1080,
                "server_host": "127.0.0.1",
                "server_port": 1081,
                "cipher": "xor",
                "password": 123456,
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
                description='Yet another tunnel proxy',
                prog='fsocks')
        parser.add_argument('-c', '--config',
                            required=True, help='path to config file')
        args = parser.parse_args()
        logger.info('Loading config {}'.format(args.config))
        with open(args.config) as f:
            _cfg = json.load(f)
        self.raw = {**self.raw, **_cfg}
        for key in self.raw:
            setattr(self, key, self.raw[key])


config = Config()
