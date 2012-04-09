"""
-=HUBCITYLABS=-
H.I.K.A.R.U. Module: Gatekeeper

By: Jean-Francois Arseneau, jf.arseneau _at_ gmail dot com

Description:
Scripts that checks in a Mongo database if the incoming card ID is associated toa member, and sends back a signal indicating whether access is granted or not.

Socket code originally lifted from http://ilab.cs.byu.edu/python/socket/echoserver.html and then modified.
"""

import socket
import ConfigParser
import hashlib
from pymongo import Connection

# Grab the info from the config
config = ConfigParser.ConfigParser()
config.read("server.cfg")

# Server Configs
host       = config.get('Server','host')
port       = config.getint('Server','port')
backlog    = 5
size       = 1024

# MongoDB Configs
mongo_host = config.get('Mongo', 'host')
mongo_port = config.getint('Mongo', 'port')
connection = Connection(mongo_host, mongo_port)
db         = connection[mongo_db]

# Crypto Config
salt = config.get('Crypto', 'salt')

# Get the server up!
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host,port))
sock.listen(backlog)

# Keep listening until the server dies
while 1:
    client, address = sock.accept()
    data = client.recv(size)
    if data:
        # All card IDs in the database are stored as SHA-256 hex digests.
        cryptoedData = hashlib.sha256(salt+data)
        collection = db.foo
        results = collection.find_one({"card_id":cryptoedData.hexdigest()})
        
        # This is where it would actually send data back to the door lock.
        # Temporary print code for now.
        if results:
            print results['name']+' has accessed the space!'
        else:
            print "Access denied!"
        
        client.send(str(cryptoedData.hexdigest()))
    client.close()

