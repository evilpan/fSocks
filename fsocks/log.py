#!/usr/bin/env python3
import logging


__all__ = ['logger']


_formater = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
_handler = logging.StreamHandler()
_handler.setFormatter(_formater)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(_handler)
