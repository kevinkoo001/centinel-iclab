#!/usr/bin/env python

import sys
import logging

from sirocco.server import Server
from utils.logger import *

if len(sys.argv) > 1 and "--local" in sys.argv:
    local_server = True
else:
    local_server = False

if len(sys.argv) > 1 and "--no-tls" in sys.argv:
    tls = True
else:
    tls = False
try:
    print open("sirocco_server_ascii_art", "r").read()
    logging.basicConfig(filename="server.log", level=logging.DEBUG)
    server = Server(local=local_server, disable_tls = tls)
    server.run()
except Exception as e:
    log("e", "Error running server: " + str(e))
