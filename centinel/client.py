import sys
sys.path.append("../")

import math
from time import gmtime, strftime
import os
import shutil
import random
import string
from os import listdir
import StringIO
import bz2
import gzip
import glob
from datetime import datetime, timedelta
from os.path import exists,isfile, join
import socket, ssl, pprint
import M2Crypto

from utils.rsacrypt import RSACrypt
from utils.aescrypt import AESCipher
from utils.colors import bcolors
from utils.colors import update_progress
from utils.logger import *
from utils.netlib import *
from client_config import client_conf
from Crypto.Hash import MD5

conf = client_conf()

class ServerConnection:
    
    def __init__(self, server_addresses = conf['server_addresses'], server_port = int(conf['server_port'])):
	self.server_addresses = server_addresses.split(" ")
	self.server_address = ""
	self.server_port = server_port
	self.connected = False
	self.aes_secret = ""
	
    def connect(self, do_login = True):
	if self.connected:
	    return True

	self.connected = False
	for address in self.server_addresses:
	    try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		self.serversocket = ssl.wrap_socket(s,
                    				    #ca_certs="/etc/ssl/certs/ca-certificates.crt",
                        			    #cert_reqs=ssl.CERT_REQUIRED,
						    ssl_version=ssl.PROTOCOL_TLSv1
    						   )

		self.serversocket.connect((address, self.server_port))
		self.connected = True
		self.server_address = [ address, self.server_port ]
		break
    	    except socket.error, (value,message): 
    		if self.serversocket: 
    		    self.serversocket.close() 
    		log("e", "Could not connect to server (%s:%s): " %(address, self.server_port) + message )
		self.connected = False
	if not self.connected:
	    return False
	else:
	    log("s", "Connected to %s:%s." %(self.server_address[0], self.server_port) )

	self.connected = True
	# Don't wait more than 15 seconds for the server.
	self.serversocket.settimeout(int(conf['timeout']))
	log("i", "Server connection successful.")
	if do_login:
	    try:
		self.logged_in = self.login()
	    except Exception as e:
		log("e", "Error logging in: " + str(e))
		self.logged_in = False
	else:
	    self.logged_in = False
	self.connected = True
	return True

    def disconnect(self):
	if not self.connected:
	    return True
	if self.serversocket:
	    log("w", "Closing connection to the server.")
	    try:
		#no need to authenticate when closing...
		send_fixed(self.serversocket, self.server_address, "x")
	    except:
		pass
	    self.serversocket.close()
	    self.connected = False


    def login(self):

	try:
	    received_server_cert = ssl.DER_cert_to_PEM_cert(self.serversocket.getpeercert(True))
	
	    if received_server_cert != open(conf["server_certificate"], "r").read():
		raise Exception("Server certificate can not be recognized!")
	    x509 = M2Crypto.X509.load_cert_string(received_server_cert)
	    
	    log("w", "Server certificate details: " + pprint.pformat(x509.get_subject().as_text()))
	except Exception as e:
	    raise Exception("Error verifying server certificate: " + str(e))

	try:
	    log("i", "Authenticating with the server...")
	    send_dyn(self.serversocket, self.server_address, conf['client_tag'])
	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	except Exception as e:
	    log("e", "Can't authenticate: " + str(e)) 
	    return False
	
	if server_response == "a":
	    log("s", "Authentication successful.")
	elif server_response == "e":
	    raise Exception("Authentication error (could not receive error details from the server).")
	else:
	    raise Exception("Unknown server response \"" + server_response + "\"")

	return True

    def check_for_updates(self):
	try:
	    client_version = open(".version", "r").read()
	    send_fixed(self.serversocket, self.server_address, "v")
	    send_dyn(self.serversocket, self.server_address, client_version)
	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	except Exception as e:
	    raise Exception("Error checking for updates: " + str(e))

	if server_response == "u":
	    log("w", "There is a newer version of Centinel available.")
	    log("i", "Downloading update package...")
	    try:
	        update_package_contents = receive_md5_checked(self.serversocket, self.server_address, show_progress=True)
		of = open("update.tar.bz2", "w")
		of.write(update_package_contents)
		of.close()
	    except Exception as e:
	        raise Exception("Error downloading update package: " + str(e))
	    return True
	elif server_response == "a":
	    return False
	else:
	    raise Exception("Error checking for updates: server response not recognized!")
		

    def send_file(self, name, file_path, message):
	if not self.connected:
	    raise Exception("Server not connected.")

	if conf['client_tag'] == 'unauthorized':
	    raise Exception("Client not authorized to send files.")

	if not self.logged_in:
	    raise Exception("Client not logged in.")

	try:
	    send_fixed(self.serversocket, self.server_address, message)
	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	except Exception as e:
	    raise Exception("Can't submit file: " + str(e))
	    return False

	if server_response == "a":
	    #log("s", "Server ack received.")
	    pass
	elif server_response == "e":
	    raise Exception("Server error.")
	    return False
	else:
	    raise Exception("Unknown server response \"" + server_response + "\"")

	try:
	    try:
		data_file = open(file_path, 'r')
	    except Exception as e:
		raise Exception("Can not open file \"%s\": " %(file_path) + str(e))
	    
	    data = data_file.read()
	    send_dyn(self.serversocket, self.server_address, name)
	    send_md5_checked(self.serversocket, self.server_address, data)

	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	    if server_response <> "a":
		raise Exception("Success message not received.")
	except Exception as e:
	    raise Exception("Error sending file to server: " + str(e))

	return True

    def initialize_client(self):
	
	try:
	    received_server_cert = ssl.DER_cert_to_PEM_cert(self.serversocket.getpeercert(True))
	
	    x509 = M2Crypto.X509.load_cert_string(received_server_cert)
	    log("w", "Server certificate details: " + pprint.pformat(x509.get_subject().as_text()))

	    of = open(conf["server_certificate"], "w")
	    of.write(received_server_cert)
	    of.close()
	except Exception as e:
	    raise Exception("Can not write server certificate: " + str(e))

	try:

	    send_dyn(self.serversocket, self.server_address, "unauthorized")
	    receive_fixed(self.serversocket, self.server_address, 1)
	    send_fixed(self.serversocket, self.server_address, "i")
	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	except Exception as e:
	    raise Exception("Can\'t initialize: " + str(e))

	if server_response == "a":
	    #log("s", "Server ack received.")
	    pass
	elif server_response == "e":
	    raise Exception("Server error (could not receive error details from the server).")
	else:
	    raise Exception("Unknown server response \"" + server_response + "\"")

	try:
	    #new_identity = receive_dyn(self.serversocket, self.server_address, crypt.private_key_string()) #identities are usually of length 5
	    new_identity = receive_dyn(self.serversocket, self.server_address) #identities are usually of length 5

	    server_response = receive_fixed(self.serversocket, self.server_address, 1)

	    #conf['client_tag'] = new_identity
	    conf.set("client_tag",new_identity)
	    if server_response == "c":
		log("s", "Server certificate download and handshake successful. New tag: " + new_identity)
		conf.set("client_tag",new_identity)
		conf.update()

	    elif server_response == "e":
		raise Exception("Server error.")
	    else:
		raise Exception("Unknown server response \"" + server_response + "\"")
	except Exception as e:
	    raise Exception("Initialization error: " + str(e))
	
    def beat(self):
	if not self.connected:
	    raise Exception("Server not connected.")

	if conf['client_tag'] == 'unauthorized':
	    raise Exception("Client not authorized to send heartbeat.")

	try:
	    send_fixed(self.serversocket, self.server_address, 'b')
	    server_response = receive_fixed(self.serversocket, self.server_address, 1)
	    
	    if server_response == 'b':
		return "beat"
	    elif server_response == 'c':
		return receive_md5_checked(self.serversocket, self.server_address, show_progress=False)
	    else:
		raise Exception("Server response not recognized.")
	except Exception as e:
	    raise Exception("Heartbeat error: " + str(e))

    def send_logs(self):
	successful = 0
	total = 0
	if not os.path.exists(conf['logs_dir']):
    	    log("i", "Creating logs directory in %s" % (conf['logs_dir']))
    	    os.makedirs(conf['results_archive_dir'])

	for log_name in listdir(conf['logs_dir']):
	    if isfile(join(conf['logs_dir'],log_name)):
		log("i", "Sending \"" + log_name + "\"...")
		total = total + 1
		try:
		    self.send_file(log_name, join(conf['logs_dir'], log_name), "g")
		    log("s", "Sent \"" + log_name + "\" to the server.")
		    os.remove(os.path.join(conf['logs_dir'], log_name))
		    successful = successful + 1
		except Exception as e:
		    log("e", "There was an error while sending \"" + log_name + "\": %s. Will retry later." %(str(e)))

	if total:
	    log("s", "Sending logs complete (%d/%d were successful)." %(successful, total))
	else:
	    pass
	    #log("i", "Sending logs complete (nothing sent).")

    def sync_results(self):
	successful = 0
	total = 0
	if conf["archive_sent_results"] == "1" and not os.path.exists(conf['results_archive_dir']):
    	    log("i", "Creating results directory in %s" % (conf['results_archive_dir']))
    	    os.makedirs(conf['results_archive_dir'])

	for result_name in listdir(conf['results_dir']):
	    if isfile(join(conf['results_dir'],result_name)):
		log("i", "Submitting \"" + result_name + "\"...")
		total = total + 1
		try:
		    self.send_file(result_name, join(conf['results_dir'], result_name), "r")
		    if conf["archive_sent_results"] == "1":
			try:
			    shutil.move(os.path.join(conf['results_dir'], result_name), os.path.join(conf['results_archive_dir'], result_name))
			    log("s", "Moved \"" + result_name + "\" to the archive.")
			except:
			    log("e", "There was an error while moving \"" + result_name + "\" to the archive. This will be re-sent the next time.")
		    else:
			try:
			    os.remove(os.path.join(conf['results_dir'], result_name))
			except:
			    log("e", "There was an error while removing \"" + result_name + "\". This will be re-sent the next time.")
		    successful = successful + 1
		except Exception as e:
		    log("e", "There was an error while sending \"" + result_name + "\": %s. Will retry later." %(str(e)))
	if total:
	    log("s", "Sync complete (%d/%d were successful)." %(successful, total))
	else:
	    pass
	    #log("i", "Sync complete (nothing sent).")


    def sync_experiments(self):
	if not self.connected:
	    raise Exception("Server not connected.")

	if conf['client_tag'] == 'unauthorized':
	    raise Exception("Client not authorized to sync experiments.")

	send_fixed(self.serversocket, self.server_address, "s")
	
	try:
	    cur_exp_list = [os.path.basename(path) for path in glob.glob(os.path.join(conf['remote_experiments_dir'], '*.py'))]
	    cur_exp_list += [os.path.basename(path) for path in glob.glob(os.path.join(conf['remote_experiments_dir'], '*.cfg'))]

	    msg = ""
	    changed = False
	    for exp in cur_exp_list:
		exp_content = open(os.path.join(conf['remote_experiments_dir'], exp), 'r').read()
		msg = msg + exp + "%" + MD5.new(exp_content).digest() + "|"
	
	    if msg:
		send_md5_checked(self.serversocket, self.server_address, msg[:-1])
	    else:
		send_md5_checked(self.serversocket, self.server_address, "n")

	    new_exp_count = receive_dyn(self.serversocket, self.server_address, )
	
	    i = int(new_exp_count)

	    if i <> 0:
		changed = True
		log("i", "%d new experiments." %(i))
		log("i", "Updating experiments...")
		while i > 0:
		    try:
			i = i - 1
			exp_name = receive_dyn(self.serversocket, self.server_address)
			exp_content = receive_md5_checked(self.serversocket, self.server_address, show_progress = True)
			f = open(os.path.join(conf['remote_experiments_dir'], exp_name), "w")
			f.write(exp_content)
			f.close()
			log("s", "\"%s\" received (%d/%d)." %(exp_name, int(new_exp_count) - i, int(new_exp_count)))
		    except Exception as e:
			try:
			    log("e", "Error downloading \"%s\" (%d/%d): " %(exp_name, int(new_exp_count) - i, int(new_exp_count)) + str(e))
			except:
			    log("e", "Error downloading experiment %d of %d." %(int(new_exp_count) - i, int(new_exp_count)) + str(e))
	except Exception as e:
	    raise Exception("Error downloading new experiments: " + str(e))

	try:
    	    old_list = receive_md5_checked(self.serversocket, self.server_address, show_progress = False)

	    if old_list <> "n":
		changed = True
		log("i", "Removing old experiments...")
		for exp in old_list.split("|"):
		    try:
			if exp:
			    os.remove(os.path.join(conf['remote_experiments_dir'], exp))
			    log("i", "Removed %s." %(exp))
		    except Exception as e:
			log("e", "Error removing %s." %(exp))

	except Exception as e:
	    raise Exception("Error removing old experiments: " + str(e))
	
	try:
	    cur_exp_data_list = [os.path.basename(path) for path in glob.glob(os.path.join(conf['experiment_data_dir'], '*.txt'))]

	    msg = ""

	    for exp_data in cur_exp_data_list:
		exp_data_contents = open(os.path.join(conf['experiment_data_dir'], exp_data), 'r').read()
		msg = msg + exp_data + "%" + MD5.new(exp_data_contents).digest() + "|"
	
	    if msg:
		send_md5_checked(self.serversocket, self.server_address, msg[:-1])
	    else:
		send_md5_checked(self.serversocket, self.server_address, "n")
	    new_exp_data_count = receive_dyn(self.serversocket, self.server_address, )
	
	    i = int(new_exp_data_count)

	    if i <> 0:
		changed = True
		log("i", "%d new experiment data files." %(i))
		log("i", "Updating experiment data files...")
		while i > 0:
		    try:
			exp_data_name = receive_dyn(self.serversocket, self.server_address, show_progress = False)
			exp_data_content = receive_md5_checked(self.serversocket, self.server_address, show_progress = True)
			f = open(os.path.join(conf['experiment_data_dir'], exp_data_name), "w")
			f.write(exp_data_content)
			f.close()
			i = i - 1
			log("s", "\"%s\" received (%d/%d)." %(exp_data_name, int(new_exp_data_count) - i, int(new_exp_data_count)))
		    except Exception as e:
			log("e", "Error downloading \"%s\" (%d/%d): " %(exp_data_name, int(new_exp_data_count) - i, int(new_exp_data_count)) + str(e))
	except Exception as e:
	    raise Exception("Error downloading new experiment data files: " + str(e))

	try:
    	    old_list = receive_md5_checked(self.serversocket, self.server_address, show_progress = False)

	    if old_list <> "n":
		changed = True
		log("i", "Removing old experiment data files...")
		for exp_data in old_list.split("|"):
		    try:
			if exp_data:
			    os.remove(os.path.join(conf['experiment_data_dir'], exp_data))
			    log("i", "Removed \"%s\"." %(exp_data))
		    except Exception as e:
			log("e", "Error removing \"%s\"." %(exp_data))

	except Exception as e:
	    raise Exception("Error removing old experiment data files: " + str(e))

	if changed:
	    log("s", "Experiments updated.")
	return True
