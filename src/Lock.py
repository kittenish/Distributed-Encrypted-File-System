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

class LockServer(object):

	def __init__(self, host=None, port=None):
		self.port = port;
		self.srvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.srvsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		self.srvsock.bind((host, port))
		self.srvsock.listen(5)
		self.Clients = [self.srvsock]
		self.write_lock = {}
		self.read_lock = {}
		print 'LockNode server started on port %s' % port

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
						
						if message['type'] == str(WRITE_LOCK):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in getting lock.'
								sock.sendall('0')
							elif self.write_lock.has_key(message['fname']) or self.read_lock.has_key(message['fname']):
								sock.sendall('0')
							else:
								self.write_lock[message['fname']] = 1
								sock.sendall('1')

						elif message['type'] == str(WRITE_RELEASE):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in getting lock.'
								sock.sendall('0')
							else:
								del self.write_lock[message['fname']]
								sock.sendall('1')

						elif message['type'] == str(READ_LOCK):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in getting lock.'
								sock.sendall('0')
							elif self.write_lock.has_key(message['fname']):
								sock.sendall('0')
							else:
								if self.read_lock.has_key(message['fname']):
									self.read_lock[message['fname']] += 1
								else:
									self.read_lock[message['fname']] = 1
								sock.sendall('1')

						elif message['type'] == str(READ_RELEASE):
							if message['check'] != hash(str(message['fname'])) & 0xffff:
								print 'Error in getting lock.'
								sock.sendall('0')
							elif self.read_lock[message['fname']] == 1:
								del self.read_lock[message['fname']]
								sock.sendall('1')
							else:
								self.read_lock[message['fname']] -= 1
								sock.sendall('1')

	
	def accept_new_client(self):
		newsock, (remhost, remport) = self.srvsock.accept()
		self.Clients.append(newsock)
