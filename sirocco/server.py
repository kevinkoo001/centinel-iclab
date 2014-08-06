import sys
from subprocess import call
sys.path.append("../")
import math
import time
from time import strftime
import os
import shutil
from os import listdir
from os.path import exists,isfile, join
import StringIO
import string
import random
import gzip
import socket, ssl
from socket import timeout
import threading
import glob
from datetime import datetime, timedelta
from Crypto.Hash import MD5
from server_config import server_conf

from utils.rsacrypt import RSACrypt
from utils.aescrypt import AESCipher
from utils.colors import bcolors
from utils.colors import update_progress
from utils.logger import *
from utils.onlineapis import geolocate, getmyip, getESTTime
from utils.netlib import *

import requests
import json
import pprint
import base64


conf = server_conf()

class Server:
    def __init__(self, local = False, disable_tls=False, sock=None):
	if sock is None:
	    #create an INET, STREAMing socket
    	    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	else:
	    self.sock = sock
	self.disable_tls = disable_tls
	self.sock.bind(('0.0.0.0', int(conf['server_port'])))
	self.sock.listen(5)

    	self.kobra_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	self.kobra_sock.bind(('0.0.0.0', int(conf['kobra_port'])))
	self.kobra_sock.listen(5)

	self.local_only = local
	self.version = open(".version", "r").read()
	self.clientsockets = list()
	self.prepare_update()
	
	"""
	Fill in the list of clients and their respective RSA public keys (currently read from files).
	TODO:
	Read from database.
	"""
	self.client_list = [os.path.splitext(os.path.basename(path))[0] for path in glob.glob(os.path.join(conf['client_keys_dir'], '*'))]
	self.kobra_users_list = [user_pass_pair.split(",")[0] for user_pass_pair in open(conf['kobra_users_file'], 'r').read().split("\n") if user_pass_pair ]
	self.kobra_passwords = dict((user_pass_pair.split(",")[0],user_pass_pair.split(",")[1])  for user_pass_pair in open(conf['kobra_users_file'], 'r').read().split("\n") if user_pass_pair )
#	self.client_keys = dict()
#	self.client_keys = dict((c, open(os.path.join(conf['client_keys_dir'],c), 'r').read()) for c in self.client_list)
	self.client_commands = dict((c, "chill") for c in self.client_list)
	self.client_exps = dict((c, []) for c in self.client_list)
	self.client_last_seen = dict((c, ("", "nowhere")) for c in self.client_list)

    """
    This runs ths server daemon.
	Each connection is handled in a separate thread.
	Keyboard and system interrupts are catched and dealt with 
	to ensure smooth and clean shutdown of the server.
    """
    def run(self):
	"""
	The server will not run if the private and the public keys are 
	not read.
	"""
#	kf = open(conf['public_rsa_file'])
#	self.public_key = kf.read()
#	kf.close()
#	kf = open(conf['private_rsa_file'])
#	self.private_key = kf.read()
#	kf.close()
	
	log("i", "Sirocco server running. Awaiting connections...")
	if self.local_only:
	    log("w", "Running in local-only mode, remote connections will be denied!")

	kobra_thread = threading.Thread(target=self.kobra_run, args = ())
	kobra_thread.daemon = True
	kobra_thread.start()

	try:
	    while 1:
		#accept connections from outside
		(newsocket, address) = self.sock.accept()

		#TLS wrap
		if not self.disable_tls:
		    try:
			clientsocket = ssl.wrap_socket(newsocket, server_side=True, certfile=conf["server_certificate"], keyfile=conf["server_key"], ssl_version=ssl.PROTOCOL_TLSv1)
		    except Exception as e:
			log("e", "Error wrapping connection in TLS: " + str(e), address)
			if newsocket:
			    newsocket.close()
			continue
		else:
		    clientsocket = newsocket

		self.clientsockets.append(clientsocket)
		log("s", "Got a connection.", address = address)
		client_thread = threading.Thread(target=self.client_connection_handler, args = (clientsocket, address))
		client_thread.daemon = True
		client_thread.start()
	except (KeyboardInterrupt, SystemExit):
	    log("w", "Shutdown requested, shutting server down...")
	    # do some shutdown stuff, then close

	    for csocket in self.clientsockets:
		if csocket:
		    csocket.close()
	    exit(0)

    def kobra_run(self):
	try:
	    while 1:
		#accept connections from outside
		(clientsocket, address) = self.kobra_sock.accept()
		self.clientsockets.append(clientsocket)
		log("s", "Got a connection.", address = address)
		kobra_user_thread = threading.Thread(target=self.kobra_connection_handler, args = (clientsocket, address))
		kobra_user_thread.daemon = True
		kobra_user_thread.start()
	except (KeyboardInterrupt, SystemExit):
	    log("w", "Shutdown requested, shutting server down...")
	    # do some shutdown stuff, then close

	    for csocket in self.clientsockets:
		if csocket:
		    csocket.close()
	    exit(0)

    def kobra_connection_handler(self, clientsocket, address):
	# We don't want to wait too long for a response.
	clientsocket.settimeout(20)
	
	if self.local_only and (address[0].split(".")[0] != "127" and self.local_only and address[0].split(".")[0] != "10"):
	    log("i", "Running in local-only mode, denying connection...", address)
	    if clientsocket:
		clientsocket.close()
	    return

	unauthorized = False
	username = ""
	aes_secret = ""
 
	if not username:
	    log("i", "Authenticating with Kobra...", address = address)
	    try:
		username = receive_dyn(clientsocket, address)
    
		authenticated = False

		random_token = ""
		received_token = ""

		if username not in self.kobra_users_list:
		    authenticated = False
		    send_fixed(clientsocket, address, "e")
		    raise Exception("Username \"%s\" not found!" %(username))
		else:
		    unauthorized = False
		    # the token is going to be used as AES secret, so it has to be correct block size
		    random_token = self.random_string_generator(32)
		    send_aes_crypt(clientsocket, address, random_token, self.kobra_passwords[username])
		    received_token = receive_aes_crypt(clientsocket, address, self.kobra_passwords[username], show_progress=False)

		    if random_token == received_token:
	    		send_fixed(clientsocket, address, "a")
			log("s", "Kobra authentication successful.", address = address, tag = username)
			authenticated = True
			aes_secret = received_token
		    else:
	    		send_fixed(clientsocket, address, "e")
			raise Exception("Kobra password authentication failed!")
    	    except Exception as e:
	        try:
	    	    send_fixed(clientsocket, address, 'e')
		except:
	    	    pass
		if clientsocket:
		    log("w", "Closing Kobra connection.", address = address, tag=username)
		    clientsocket.close()
		log("e", "Kobra authentication error: " + str(e), address=address, tag=username)
		return

	outcome = True
	while outcome == True:
	    try:
		com = receive_aes_crypt(clientsocket, address, aes_secret, show_progress = False)
		outcome = self.kobra_command_handler(clientsocket, address, username, aes_secret, com)
	    except socket.timeout:
		pass
	    except Exception as e:
		log ("e", "Error handling Kobra command: " + str(e), address = address, tag = username)
		break
	
	# close the connection after communication ends
	if clientsocket:
	    log("w", "Closing Kobra connection.", address=address, tag=username)
	    clientsocket.close()

    def kobra_command_handler(self, clientsocket, address, username, aes_secret, com):
	try:
	    if com == "exit" or com == "quit":
		send_aes_crypt(clientsocket, address, "<END>", aes_secret)
		return False
	    send_aes_crypt(clientsocket, address, "<START_MESSAGE>", aes_secret)
	    
	    if com == "update_centinel":
		latest_version = open(".version", "r").read()
		if self.version <> latest_version:
		    log("i", "Centinel has been updated, creating new update package...")
		    send_aes_crypt(clientsocket, address, "Centinel has been updated, creating new update package...", aes_secret)
		    self.prepare_update()
		    self.version = latest_version
		else:
		    send_aes_crypt(clientsocket, address, "Centinel is up to date.", aes_secret)
		    
	    elif com == "listclients":
		send_aes_crypt(clientsocket, address, "Connected clients: ", aes_secret)
		for client, (lasttime, lastaddress) in self.client_last_seen.items():
		    if lasttime <> "":
		        if datetime.now() - lasttime < timedelta(seconds=60):
			    send_aes_crypt(clientsocket, address, "%s\t%s\t\t%s(%d seconds ago)\t\t%s" %(client, lastaddress, lasttime.strftime("%Y-%m-%d %H:%M:%S"), (datetime.now() - lasttime).seconds, (geolocate(lastaddress)[0]+", "+geolocate(lastaddress)[1]) if geolocate(lastaddress) else "" ), aes_secret)
		    
		send_aes_crypt(clientsocket, address,  "Disconnected clients: ", aes_secret)
		for client, (lasttime, lastaddress) in self.client_last_seen.items():
		    if not lasttime or datetime.now() - lasttime >= timedelta(seconds=60):
		        send_aes_crypt(clientsocket, address,  "%s\t%s\t\t%s(%s seconds ago)\t\t%s" %(client, lastaddress, lasttime.strftime("%Y-%m-%d %H:%M:%S") if lasttime else "never", str((datetime.now() - lasttime).seconds) if lasttime else "infinite",(geolocate(lastaddress)[0]+", "+geolocate(lastaddress)[1]) if geolocate(lastaddress) else "" ), aes_secret)

	    elif len(com.split()) == 2 and com.split()[0] == "listresults":
		tag = com.split()[1]
		if not os.path.exists(os.path.join(conf['results_dir'], tag)):
		    send_aes_crypt(clientsocket, address,  "Client results directory not found.", aes_secret)
		else:
		    for path in glob.glob(os.path.join(conf['results_dir'], tag + '/*.json')):
			results = json.loads(open(path,'r').read())
			#pp = pprint.PrettyPrinter(indent=2)
			#results["std_http"][0]["response"]["body"] = base64.b64decode(results["std_http"][0]["response"]["body"])
			#pp.pprint(results)
			send_aes_crypt(clientsocket, address, (results["meta"]["exp_name"] + ":\t" + results["meta"]["run_id"] + "\t" + results["meta"]["local_time"]).encode("utf8"), aes_secret)

	    elif len(com.split()) == 4 and com.split()[0] == "printresults":
		tag = com.split()[1]
		experiment_name = com.split()[2]
		run_id = com.split()[3]
		if not os.path.exists(os.path.join(conf['results_dir'], tag)):
		    send_aes_crypt(clientsocket, address,  "Client results directory not found.", aes_secret)
		else:
		    found = False
		    for path in glob.glob(os.path.join(conf['results_dir'], tag + '/*.json')):
			results = json.loads(open(path,'r').read())
			if results["meta"]["exp_name"] == experiment_name and results["meta"]["run_id"] == run_id:
			    pp = pprint.PrettyPrinter(indent=2)
			    results["std_http"][0]["response"]["body"] = base64.b64decode(results["std_http"][0]["response"]["body"])
			    formatted = pp.pformat(results).replace('\\n', '\n')
			    send_aes_crypt(clientsocket, address, (formatted).encode("utf8"), aes_secret)
			    found = True
		    if not found:
			send_aes_crypt(clientsocket, address, "Experiment and run ID not found!" , aes_secret)
	    elif len(com.split()) > 2:
		tag, command_list = com.split(" ", 1);
		if tag in self.client_list and command_list <> "chill" and command_list:
		    if self.client_commands[tag] == "chill":
			self.client_commands[tag] = command_list
		    else:
			self.client_commands[tag] = self.client_commands[tag] + "; " + command_list
		    log("s", "Scheduled command list \"%s\" to be run on %s. (last seen %s at %s)" %(self.client_commands[tag],tag, self.client_last_seen[tag][0], self.client_last_seen[tag][1]), tag=tag)
		    send_aes_crypt(clientsocket, address, "Scheduled command list \"%s\" to be run on %s. (last seen %s at %s)" %(self.client_commands[tag],tag, self.client_last_seen[tag][0], self.client_last_seen[tag][1]), aes_secret)
		elif tag == "onall" and command_list <> "chill" and command_list:
		    for client in self.client_list:
			if self.client_commands[client] == "chill":
			    self.client_commands[client] = command_list
			else:
			    self.client_commands[client] = self.client_commands[client] + "; " + command_list
		    log("s", "Scheduled command list \"%s\" to be run on all clients." %(command_list))
		    send_aes_crypt(clientsocket, address, "Scheduled command list \"%s\" to be run on all clients." %(command_list), aes_secret)
	    else:
		send_aes_crypt(clientsocket, address, "Command \"%s\" not recognized." %(com), aes_secret)

	    send_aes_crypt(clientsocket, address, "<END_MESSAGE>", aes_secret)
	    return True
	except Exception as e:
	    log ("e", "Error handling Kobra command \"%s\": " %(com) + str(e))
	    return False

    """
    This will handle all client requests as a separate thread.
	Clients will be authenticated and have their commands handled.
    """
    def client_connection_handler(self, clientsocket, address):
	# r: send results
	# s: sync experiments
	# b: heartbeat and get commands
	# x: close connection (can be done using "unauthorized" tag)
	# i: initialize client (can be done using "unauthorized" tag)

	# We don't want to wait too long for a response.
	clientsocket.settimeout(20)
	
	if self.local_only and (address[0].split(".")[0] != "127" and self.local_only and address[0].split(".")[0] != "10"):
	    log("i", "Running in local-only mode, denying connection...", address)
	    if clientsocket:
		clientsocket.close()
	    return

	unauthorized = False
	authenticated = False
	client_tag = ""
	aes_secret = ""

	if not client_tag:
	    log("i", "Authenticating...", address = address)
	    try:
		client_tag = receive_dyn(clientsocket, address)
    
		authenticated = False

		if client_tag == "unauthorized":
		    # Only allow them to either close or initialize:
		    unauthorized = True

		if unauthorized or (client_tag in self.client_list):
		    if client_tag <> "unauthorized":
			log("s", "Authentication successful.", address = address, tag = client_tag)
			authenticated = True
		    else:
			log("w", "Unauthorized client connected...", address = address)

		    send_fixed(clientsocket, address, "a")
		else:
		    raise Exception("Authentication error.")
    	    except Exception as e:
	        try:
	    	    send_fixed(clientsocket, address, 'e')
		except:
	    	    pass
		if clientsocket:
		    log("w", "Closing connection.", address = address, tag = client_tag)
		    clientsocket.close()
		log("e", "Authentication error: " + str(e), address=address, tag=client_tag)
		return

	outcome = True
	while outcome == True:
	    try:
		outcome = self.handle_client_requests(clientsocket, address, client_tag, unauthorized)
	    except Exception as e:
		log ("e", "Error handling client request: " + str(e), address = address, tag = client_tag)
		break
	
	# close the connection after communication ends
	if clientsocket:
	    log("w", "Closing connection.", address=address, tag=client_tag)
	    clientsocket.close()

    def handle_client_requests(self, clientsocket, address, client_tag, unauthorized = True):
	message_type = ""
	
	client_took_long = False
	while not message_type:
	    try:
		message_type = receive_fixed(clientsocket, address, 1)
	    except timeout:
		if not client_took_long:
		    log("w", "Client is taking a bit too long to send command... ", address = address, tag = client_tag)
		    client_took_long = True
	
	if client_took_long:
	    log("i", "Client is back online.", address = address, tag = client_tag)
    	if not unauthorized:
	    self.client_last_seen[client_tag] = datetime.now() , address[0] + ":" + str(address[1])

	# The client wants to submit results:
	if message_type == "r" and not unauthorized:
	    log("i", "Client wants to submit results.", address = address, tag = client_tag)
	    try:
    		send_fixed(clientsocket, address, "a")

		results_name = receive_dyn(clientsocket, address)
		results_data = receive_md5_checked(clientsocket, address, show_progress = True)

		if not os.path.exists(conf['results_dir']):
    		    log("i", "Creating results directory in %s" % (conf['results_dir']), address, client_tag)
    		    os.makedirs(conf['results_dir'])

		if not os.path.exists(os.path.join(conf['results_dir'], client_tag)):
    		    log("i", "Creating results directory in %s" % (os.path.join(conf['results_dir'], client_tag)), address, client_tag)
    		    os.makedirs(os.path.join(conf['results_dir'], client_tag))

		out_file = open(os.path.join(conf['results_dir'], client_tag + "/" + datetime.now().isoformat() + "-" + results_name), 'w')
		out_file.write(results_data)
		out_file.close()
		send_fixed(clientsocket, address, "a")
	    except Exception as e:
		try:
		    send_fixed(clientsocket, address, "e")
		except:
		    pass
    		log("e", "Error receiving results data: " + str(e), address, client_tag)

	    log("s", "Results file \"%s\" received successfully." %(results_name), address, client_tag)
	    return True

	# The client wants to send log files:
	elif message_type == "g" and not unauthorized:
	    log("i", "Client wants to send log files.", address = address, tag = client_tag)
	    try:
    		send_fixed(clientsocket, address, "a")

		log_name = receive_dyn(clientsocket, address)
		log_decrypted = receive_md5_checked(clientsocket, address, show_progress = True)

		if not os.path.exists(conf['log_archive_dir']):
    		    log("i", "Creating log directory in %s" % (conf['log_archive_dir']), address, client_tag)
    		    os.makedirs(conf['log_archive_dir'])

		out_file = open(os.path.join(conf['log_archive_dir'], client_tag + "-" + log_name), 'w')
		out_file.write(log_decrypted)
		out_file.close()
		send_fixed(clientsocket, address, "a")
	    except Exception as e:
		try:
		    send_fixed(clientsocket, address, "e", address, client_tag)
		except:
		    pass
    		log("e", "Error receiving log file: " + str(e))
	    log("s", "Log file \"%s\" received successfully." %(log_name), address, client_tag)
	    return True


	# The client wants to end the connection.
	elif message_type == "x":
	    log("i", "Client wants to close the connection.", address = address, tag = client_tag)
	    return False
	
	# The client wants to check for updates.
	elif message_type == "v":
	    #log("i", "Client wants to check for updates.", address = address, tag = client_tag)
	    latest_version = open(".version", "r").read()
	    if self.version <> latest_version:
	        log("i", "Centinel has been updated, creating new update package...", address, client_tag)
	        self.prepare_update()
		self.version = latest_version
	    try:
    		client_version = receive_dyn(clientsocket, address)
	    except Exception as e:
		log("e", "Error getting client version: " + str(e), address = address, tag = client_tag)
		return False
	    if client_version <> self.version:
		log("w", "Client is running Centinel version \"%s\", newest version is \"%s\". Updating..." %(client_version, self.version), address, client_tag)
		try:
		    send_update(clientsocket, address, client_tag)
		    log("s", "Sent the latest Centinel package to the client, closing connection...", address, client_tag)
		    return False
		except Exception as e:
		    log("e", "Error sending the update package to the client: " + str(e), address, client_tag)
		    return False
	    else:
		try:
		    send_fixed(clientsocket, address, "a")
		except Exception as e:
		    log("e", "Error sending update message to client: " + str(e), address = address, tag = client_tag)
		return True

	# The client wants to initialize.
	elif message_type == "i":
	    log("i", "Client wants to initialize.", address = address)
	    identity = self.random_string_generator()
	    try:
		send_fixed(clientsocket, address, "a")
		send_dyn(clientsocket, address, identity) #size is usually 5 characters (it is easy to write down and/or remember)
		send_fixed(clientsocket, address, "c")
	    except Exception as e:
		try:
		    send_fixed(clientsocket, address, "e")
		    send_dyn(clientsocket, address, "Initialization error.")
		except:
		    pass
		raise Exception("Initialization error: " + str(e))

	    self.client_list.append(identity)
	    self.client_last_seen [identity] = ("", "")
	    self.client_commands [identity] = "chill"
	    self.client_exps [identity] = ""
	    client_tag = identity
	    log ("s", "Client initialized successfully. New tag: " + identity, address = address, tag = client_tag)

	    # After init, the client has to disconnect and login again.
	    return False


	# The client wants to sync experiments:
	elif message_type == "s" and not unauthorized:
	    try:
		client_exp_list = receive_md5_checked(clientsocket, address, show_progress = False)
		changed = False

		if client_exp_list == "n":
		    client_exp_list = [""]
		else:
		    client_exp_list = client_exp_list.split("|")

		updates = [x for x in self.current_exp_list(client_tag) if x not in client_exp_list]

		send_dyn(clientsocket, address, str(len(updates)))

		for exp in updates:
		    if exp:
			changed = True
			sendexp(clientsocket, address, client_tag, exp.split("%")[0])

		old_list = [x.split("%")[0] for x in client_exp_list if x.split("%")[0] not in [y.split("%")[0] for y in self.current_exp_list(client_tag)] ]

		msg = ""
		for item in old_list:
		    msg += item + "|"

		if msg:
		    changed = True
		    send_md5_checked(clientsocket, address, msg[:-1])
		else:
		    send_md5_checked(clientsocket, address, "n")

		client_exp_data_list = receive_md5_checked(clientsocket, address, show_progress = False)

		if client_exp_data_list == "n":
		    client_exp_data_list = [""]
		else:
		    client_exp_data_list = client_exp_data_list.split("|")

		updates = [x for x in self.current_exp_data_list(client_tag) if x not in client_exp_data_list]
		send_dyn(clientsocket, address, str(len(updates)))

		for exp_data in updates:
		    if exp_data:
			changed = True
			sendexp_data(clientsocket, address, client_tag, exp_data.split("%")[0])

		old_list = [x.split("%")[0] for x in client_exp_data_list if x.split("%")[0] not in [y.split("%")[0] for y in self.current_exp_data_list(client_tag)] ]

		msg = ""
		for item in old_list:
		    msg += item + "|"

		if msg:
		    changed = True
		    send_md5_checked(clientsocket, address, msg[:-1])
		else:
		    send_md5_checked(clientsocket, address, "n")
	    
		if changed:
		    log("i", "Client just updated its experiment set.", address = address, tag = client_tag)
	    except Exception as e:
		raise Exception("Error synchronizing experiments: " + str(e))

	    return True
	# The client is showing heartbeat:
	elif message_type == "b" and not unauthorized:
	    try:
		if self.client_commands[client_tag] == 'chill':
		    send_fixed(clientsocket, address, 'b')
		else:
		    send_fixed(clientsocket, address, 'c')
		    send_md5_checked(clientsocket, address, self.client_commands[client_tag])
		    log("i", "Client just received the latest commands.", address = address, tag = client_tag )
		    self.client_commands[client_tag] = "chill"
		return True
	    except Exception as e:
		raise Exception ("Error at heartbeat: " + str(e))
	else:
	    try:
		send_fixed(clientsocket, address, "e")
	    except Exception:
		pass
	    raise Exception("Message type \"%s\" not recognized." %(message_type))
	    return False

    def current_exp_list(self, client_tag):
	exp_list = list()
	exp_list += self.client_exps[client_tag]

	exp_list += [os.path.basename(path) + "%" + MD5.new(open(path,'r').read()).digest() for path in glob.glob(os.path.join(conf['experiments_dir'], '*.cfg'))]
	exp_list += [os.path.basename(path) + "%" + MD5.new(open(path,'r').read()).digest() for path in glob.glob(os.path.join(conf['experiments_dir'], '*.py' ))]
	return exp_list
	    
    def current_exp_data_list(self, client_tag):
	exp_data_list = list()

	exp_data_list += [os.path.basename(path) + "%" + MD5.new(open(path,'r').read()).digest() for path in glob.glob(os.path.join(conf['experiment_data_dir'], '*.txt'))]
	return exp_data_list

    def sendexp(self, clientsocket, address, client_tag, exp):
	f = open(os.path.join(conf['experiments_dir'], exp), 'r')
	contents = f.read()
	send_dyn(clientsocket, address, exp)
	send_md5_checked(clientsocket, address, contents)

    def sendexp_data(self, clientsocket, address, client_tag, exp):
	f = open(os.path.join(conf['experiment_data_dir'], exp), 'r')
	contents = f.read()
	send_dyn(clientsocket, address, exp)
	send_md5_checked(clientsocket, address, contents)

    def random_string_generator(self, size=5, chars=string.ascii_uppercase + string.digits):
	identifier = ''.join(random.choice(chars) for _ in range(size))
	while identifier in self.client_list:
	    identifier = ''.join(random.choice(chars) for _ in range(size))
	return identifier

    def send_update(self, clientsocket, address, client_tag):
	send_fixed(clientsocket, address, "u")
	update_package = open("centinel_latest.tar.bz2", "r").read()
	send_md5_checked(clientsocket, address, update_package)

    def prepare_update(self):
	call([conf['pack_maker_path'], ""])
	log ("i", "Uploading the update package to website...")
	r = requests.post("http://rpanah.ir/downloads/upload.php", files={"file" : ("centinel_latest.tar.bz2",open("centinel_latest.tar.bz2", "rb"))})
	log ("s", "Uploader message: " + r.content)
