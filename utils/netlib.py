import bz2, socket
import math
from Crypto.Hash import MD5
from logger import *
from datetime import datetime
from rsacrypt import RSACrypt
from aescrypt import AESCipher
from colors import *

"""
Send a string of characters on the socket.
Size is fixed, meaning that the receiving party is 
expected to know how many bytes to read.
"""
def send_fixed(clientsocket, address, data):
    try:
        sent = clientsocket.send(data)
    except Exception as det: 
        if clientsocket:
	    log("i", "Closing connection to the client.", address=address)
	    clientsocket.close()
	raise Exception("Could not send data to client (%s:%s): " %(address[0], address[1])), det
	return False
	    
    return True

"""
Receive a string of characters on the socket.
Size is fixed, meaning that we know how 
many bytes to read.
"""
def receive_fixed(clientsocket, address, message_len):
    chunks = []
    bytes_recd = 0
    while bytes_recd < message_len:
        chunk = clientsocket.recv(min(message_len - bytes_recd, 2048))
        if chunk == '':
            if clientsocket:
		log("i", "Closing connection to the client.", address = address)
		clientsocket.close()
        	raise Exception("Socket connection broken.")
		return False
	chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return ''.join(chunks)

"""
Send a string of characters on the socket.
Size is dynamic and is sent fist as a 0-padded 10-byte 
string so that the receiving end will know how many 
bytes to read.
"""
def send_dyn(clientsocket, address, data):
    send_fixed(clientsocket, address, str(len(data)).zfill(10))
    send_fixed(clientsocket, address, data)

"""
Receive a string of characters on the socket.
Size is dynamic and is sent fist as a 0-padded 10-byte 
string so that the we know how many bytes to read.
"""
def receive_dyn(clientsocket, address):
    msg_size = receive_fixed(clientsocket, address, 10)
    msg = receive_fixed(clientsocket, address, int(msg_size))
    return msg

"""
Send a string of characters with MD5 check.
The message will be chopped up into chunks of fixed size.
The number of chunks is sent, followed by the
hash of the data (used for integrity checking).
Chunks are sent one by one after that.
"""
def send_md5_checked(clientsocket, address, data):
    chunk_size = 1024
    digest = MD5.new(data).digest()
    data = data.encode("bz2")
    chunk_count = int(math.ceil(len(data) / float(chunk_size)))

    send_dyn(clientsocket, address, str(chunk_count))
    send_dyn(clientsocket, address, digest)

    bytes_sent = 0
    chunk = ""
    while bytes_sent < len(data):
        chunk = data[bytes_sent:min(bytes_sent+chunk_size, len(data))]
        bytes_sent = bytes_sent + chunk_size
        send_dyn(clientsocket, address, chunk)

"""
Receive a string of characters and check them with MD5 digest.
The message will be received in chunks of fixed size.
The number of encrypted chunks is received, followed by the
hash of the unencrypted data (used for integrity checking).
Encrypted chunks are received one by one after that and 
decrypted using the given key. The resulting string is then
hashed and verified using the received hash.
"""
def receive_md5_checked(clientsocket, address, show_progress=True):
    chunk_count = int(receive_dyn(clientsocket, address))
    received_digest = receive_dyn(clientsocket, address)
    org = chunk_count
    chunk_size = 1024
    received_bytes = ""
    byte_rate = ""
    start_time = datetime.now()
    if show_progress and chunk_count:
        print bcolors.OKBLUE + "Progress: "
    while chunk_count > 0:
        chunk = receive_dyn(clientsocket, address)
        received_bytes = received_bytes + chunk
        chunk_count = chunk_count - 1
        if show_progress:
    	    time_elapsed = (datetime.now() - start_time).seconds
    	    if  time_elapsed > 0:
		byte_rate = str((float(len(received_bytes)) / float(time_elapsed)) / 1024.0)
	    update_progress( int(100 * float(org - chunk_count) / float(org)), byte_rate + " Kb/s " if byte_rate else "" )
    
    if show_progress:
        print bcolors.ENDC

    received_bytes = received_bytes.decode("bz2")

    calculated_digest = MD5.new(received_bytes).digest()
    if calculated_digest == received_digest:
        return received_bytes
    else:
        raise Exception("MD5: data integrity check failed.")
	return False


"""
Send a string of characters encrpyted using a given AES key.
The message will be chopped up into chunks of fixed size.
The number of encrypted chunks is sent, followed by the
hash of the unencrypted data (used for integrity checking).
Encrypted chunks are sent one by one after that.
"""
def send_aes_crypt(clientsocket, address, data, encryption_key):
    crypt = AESCipher(encryption_key)

    chunk_size = 1024
    chunk_count = int(math.ceil(len(data) / float(chunk_size)))
    digest = MD5.new(data).digest()

    send_dyn(clientsocket, address, str(chunk_count))
    send_dyn(clientsocket, address, digest)

    bytes_encrypted = 0
    encrypted_data = ""
    while bytes_encrypted < len(data):
	encrypted_chunk = crypt.encrypt(data[bytes_encrypted:min(bytes_encrypted+chunk_size, len(data))])
	bytes_encrypted = bytes_encrypted + chunk_size
	send_dyn(clientsocket, address, encrypted_chunk)

"""
Receive a string of characters encrpyted using a given AES key.
The message will be received in chunks of fixed size.
The number of encrypted chunks is received, followed by the
hash of the unencrypted data (used for integrity checking).
Encrypted chunks are received one by one after that and 
decrypted using the given key. The resulting string is then
hashed and verified using the received hash.
"""
def receive_aes_crypt(clientsocket, address, decryption_key, show_progress=True):
    crypt = AESCipher(decryption_key)
    chunk_count = int(receive_dyn(clientsocket, address))
    received_digest = receive_dyn(clientsocket, address)
    org = chunk_count
    chunk_size = 1024
    decrypted_results = ""
    byte_rate = ""
    start_time = datetime.now()
    if show_progress and chunk_count:
        print bcolors.OKBLUE + "Progress: "
    while chunk_count > 0:
        encrypted_chunk = receive_dyn(clientsocket, address)
        #print "\"" + encrytpted_chunk + "\""
        decrypted_results = decrypted_results + crypt.decrypt(encrypted_chunk)
        chunk_count = chunk_count - 1
        if show_progress:
    	    time_elapsed = (datetime.now() - start_time).seconds
	    if  time_elapsed > 0:
	        byte_rate = str((float(len(decrypted_results)) / float(time_elapsed)) / 1024.0)
	    update_progress( int(100 * float(org - chunk_count) / float(org)), byte_rate + " Kb/s " if byte_rate else "" )
    if show_progress:
        print bcolors.ENDC

    calculated_digest = MD5.new(decrypted_results).digest()
    if calculated_digest == received_digest:
        return decrypted_results
    else:
        raise Exception("AES: data integrity check failed.")
        return False

"""
Send a string of characters encrpyted using a given RSA key.
The message will be chopped up into chunks of fixed size.
The number of encrypted chunks is sent, followed by the
hash of the unencrypted data (used for integrity checking).
Encrypted chunks are sent one by one after that.
"""
def send_rsa_crypt(clientsocket, address, data, encryption_key):
    crypt = RSACrypt()
    crypt.import_public_key(encryption_key)

    chunk_size = 256
    chunk_count = int(math.ceil(len(data) / float(chunk_size)))
    digest = MD5.new(data).digest()

    send_dyn(clientsocket, address, str(chunk_count))
    send_dyn(clientsocket, address, digest)

    bytes_encrypted = 0
    encrypted_data = ""
    while bytes_encrypted < len(data):
        encrypted_chunk = crypt.public_key_encrypt(data[bytes_encrypted:min(bytes_encrypted+chunk_size, len(data))])
        bytes_encrypted = bytes_encrypted + chunk_size
        send_dyn(clientsocket, address, encrypted_chunk[0])

"""
Receive a string of characters encrpyted using a given RSA key.
The message will be received in chunks of fixed size.
The number of encrypted chunks is received, followed by the
hash of the unencrypted data (used for integrity checking).
Encrypted chunks are received one by one after that and 
decrypted using the given key. The resulting string is then
hashed and verified using the received hash.
"""
def receive_rsa_crypt(clientsocket, address, decryption_key, show_progress=True):
    crypt = RSACrypt()
    crypt.import_public_key(decryption_key)

    chunk_count = int(receive_dyn(clientsocket, address))
    received_digest = receive_dyn(clientsocket, address)

    org = chunk_count
    chunk_size = 256
    decrypted_results = ""
    byte_rate = ""
    start_time = datetime.now()
    if show_progress and chunk_count:
        print bcolors.OKBLUE + "Progress: "
    while chunk_count > 0:
        encrypted_chunk = receive_dyn(clientsocket, address)
        decrypted_results = decrypted_results + crypt.public_key_decrypt(encrypted_chunk)
        chunk_count = chunk_count - 1
        if show_progress:
	    time_elapsed = (datetime.now() - start_time).seconds
	    if  time_elapsed > 0:
	        byte_rate = str((float(len(decrypted_results)) / float(time_elapsed)) / 1024.0)
	    update_progress( int(100 * float(org - chunk_count) / float(org)), byte_rate + " Kb/s " if byte_rate else "" )

    if show_progress:
        print bcolors.ENDC

    calculated_digest = MD5.new(decrypted_results).digest()
    if calculated_digest == received_digest:
        return decrypted_results
    else:
        raise Exception("RSA: data integrity check failed.")
        return False
