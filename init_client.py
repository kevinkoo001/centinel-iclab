#!/usr/bin/env python

import sys
import os
from os import path
from os.path import exists
from centinel.client import ServerConnection
from centinel.client_config import client_conf
from utils.colors import bcolors
from centinel.gen_client_cert import create_self_signed_cert

c = client_conf()

print bcolors.OKBLUE + 'Initializing the client.' + bcolors.ENDC

def check_create_dir(path):
    if not os.path.exists(path):
        print "Creating directory in %s" % (path)
        os.makedirs(path)

check_create_dir(c.c['centinel_home_dir'])
check_create_dir(c.c['keys_dir'])
check_create_dir(c.c['confs_dir'])
check_create_dir(c.c['results_dir'])
check_create_dir(c.c['results_archive_dir'])
check_create_dir(c.c['logs_dir'])
check_create_dir(c.c['remote_experiments_dir'])
check_create_dir(c.c['custom_experiments_dir'])
check_create_dir(c.c['experiment_data_dir'])
check_create_dir(c.c['custom_experiment_data_dir'])

if len(sys.argv) > 1 and sys.argv[1] == "--offline":
    exit(0)

if c.config_read:
    print bcolors.FAIL + 'A configuration file already exists for %s, are you sure you want to initialize? (if so, type \'yes\') ' %(c.c['client_tag']) + bcolors.ENDC
    ans = raw_input()
    if ans.lower() <> "yes":
	print bcolors.OKBLUE + 'Nothing changed, exiting.' + bcolors.ENDC
	exit(0)

ans = raw_input("Do you want to keep experiment results after sending them to the server?")
if ans.lower() == "yes" or ans.lower() == "y" or ans.lower() == "Y":
    c.set("archive_sent_results", "1")
else:
    print "Experiment results will not be archived, you can change this by editing the configuration file at \"" + c["config_file"] + "\""
c.update()

# CREATE CLIENT CERTIFICATION WHILE INTIALIZATION PROCESS
try:
    create_self_signed_cert(c['client_certificate'], c['client_key'], c["client_tag"])
except:
    print bcolors.FAIL + "Error writing client certificate." + bcolors.ENDC
    exit(1)
	
retry = True
done = True
while retry:
    try:
	print bcolors.OKBLUE + 'Connecting to server...' + bcolors.ENDC
	serverconn = ServerConnection()
	if not serverconn.connect(do_login = False):
	    raise Exception("Could not connect.")
	serverconn.initialize_client()
	done = True
	retry = False
    except Exception as e:
	done = False
	print bcolors.FAIL + "Error initializing: " + str(e) + bcolors.ENDC
	print bcolors.OKBLUE + "Want to retry? " + bcolors.ENDC
	ans = raw_input()
	if ans.lower() == "yes" or ans.lower() == "y" or ans.lower() == "Y":
	    print bcolors.OKBLUE + 'Retrying...' + bcolors.ENDC
	    retry = True
	else:
	    retry = False
serverconn.disconnect()

if not done:
    print bcolors.FAIL + "Client not initialized!" + bcolors.ENDC
    exit(1)

