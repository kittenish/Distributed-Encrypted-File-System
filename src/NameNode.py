# coding="utf-8"
# -*- coding: utf-8 -*-
import socket
import select
import sys
import struct
import os
import datetime
import json
import random
reload(sys)
sys.setdefaultencoding('utf8')
sys.path.append("../")
from defination import *

class NameNodeServer(object):

	def __init__(self, host=None, port=None, path=None):
		self.port = port;
		self.srvsock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
		self.srvsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		self.srvsock.bind( (host, port) )
		self.srvsock.listen(5)
		self.Clients = [self.srvsock]
		self.DataNode = {}
		self.path = path
		print 'NameNode server started on port %s' % port

	def run(self):
		while 1:
			(sread, swrite, sexc) = select.select(self.Clients, [], [] )
			for sock in sread:

				if sock == self.srvsock:
					self.accept_new_client()
					
				else:
					mess = sock.recv(4);
					if mess == '':
						if sock in self.Clients:
							self.Clients.remove(sock)
						sock.close()

					else:
						length = int(mess[0:4])
						mess = sock.recv(length)
						message = eval(mess[0:length])
						
						if message['type'] == str(UPLOAD):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in inquiry.'
								continue
							try:
								with open(self.path + 'location.json', 'r') as f:
									location = json.load(f)
							except:
								with open(self.path + 'location.json', 'w') as f:
									json.dump({}, f)
									location = {}
							if location.has_key(message['fname']):
								datanode = location[message['fname']]
							else:
								datanode = {}
							
							fsize = message['fsize']								
							i = 1
							while fsize > 0:
								if datanode.has_key(str(i)):
									pass
								else:
									#datanode[i] = [DataNode_1, DataNode_2, DataNode_3]
									qualified_node = []
									for node in self.DataNode.keys():
										if int(self.DataNode[node]) > 16384:
											qualified_node.append(node)
									slice_node = random.sample(qualified_node, 3)
									datanode[str(i)] = slice_node
								i = int(i) + 1
								fsize = fsize - 16384
							location[message['fname']] = datanode
							
							with open(self.path + 'location.json', 'w') as f:
								json.dump(location, f)
								f.close()
							
							prepare_mess = {}
							prepare_mess['datanode'] = str(datanode)
							prepare_mess['check'] = hash(str(prepare_mess['datanode'])) & 0xffff
							length = str(len(str(prepare_mess))).rjust(4,'0')
							sock.sendall(length + str(prepare_mess))

						elif message['type'] == str(DOWNLOAD):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in inquiry.'
								continue
							with open(self.path + 'location.json', 'r') as f:
								location = json.load(f)

							prepare_mess = {}
							prepare_mess['datanode'] = str(location[message['fname']])
							prepare_mess['check'] = hash(str(prepare_mess['datanode'])) & 0xffff
							length = str(len(str(prepare_mess))).rjust(4,'0')
							sock.sendall(length + str(prepare_mess))

						elif message['type'] == str(DATANODE):
							self.DataNode[str(message['id'])] = int(message['size'])
							#print self.DataNode

						elif message['type'] == str(DELETE):
							with open(self.path + 'location.json', 'r') as f:
								location = json.load(f)
							del location[message['fname']]
							with open(self.path + 'location.json', 'w') as f:
								json.dump(location, f)
								f.close()

	
	def accept_new_client(self):
		newsock, (remhost, remport) = self.srvsock.accept()
		self.Clients.append(newsock)

	