#!/usr/bin/env python3
import logging


formater = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formater)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)
