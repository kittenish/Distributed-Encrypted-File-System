# coding="utf-8"
# -*- coding: utf-8 -*-
import socket
import select
import sys
import struct
import os
import datetime
reload(sys)
sys.setdefaultencoding('utf8')
sys.path.append("../")
from defination import *

class DataNodeServer(object):

	def __init__(self, host=None, port=None, path=None):
		self.port = port;
		self.srvsock = socket.socket()
		self.srvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		self.srvsock.bind((host, port))
		self.srvsock.listen(5)
		self.namenode = socket.socket()
		self.namenode.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		self.namenode.bind((host, port))
		self.namenode.connect((NAMENODEHOST, NAMENODEPORT))
		self.Clients = [self.srvsock]
		self.path = path
		self.size = 100e6
		print 'DataNode server started on port %s' % port
		prepare_mess = {}
		prepare_mess['type'] = str(DATANODE)
		prepare_mess['id'] = self.port
		prepare_mess['size'] = self.size
		length = str(len(str(prepare_mess))).rjust(4,'0')
		self.namenode.sendall(length + str(prepare_mess))
		print 'Update size to '+str(self.size)+' kb...'

	def run(self):
		while 1:
			(sread, swrite, sexc) = select.select(self.Clients, [], [] )
			for sock in sread:

				if sock == self.srvsock:
					self.accept_new_client()
					
				else:
					mess = sock.recv(8);
					if mess == '':
						if sock in self.Clients:
							self.Clients.remove(sock)
						sock.close()

					else:
						length = int(mess[0:8])
						message = sock.recv(length)
						message = eval(message[0:length])
						if message['type'] == str(WRITE):
							path = self.path + str(message['fname'])
							content = str(message['cipherfile'])
							fp = open(path,'wb')
							fp.write(content)
							fp.close()
							print 'Finish writing ' + str(message['fname'])
							self.size = self.size - os.path.getsize(path)
							prepare_mess = {}
							prepare_mess['type'] = str(DATANODE)
							prepare_mess['id'] = self.port
							prepare_mess['size'] = self.size
							length = str(len(str(prepare_mess))).rjust(4,'0')
							self.namenode.sendall(length + str(prepare_mess))
							print 'Update size to '+str(self.size)+' kb...'

						elif message['type'] == str(READ):
							path = self.path + str(message['fname'])
							fp = open(path,'rb')
							content = fp.read()
							fp.close()
							prepare_mess = {}
							prepare_mess['content'] = content
							length = str(len(str(prepare_mess))).rjust(8,'0')
							sock.sendall(length + str(prepare_mess))
							print 'Send file ' + str(message['fname'])

						elif message['type'] == str(DELETE):
							path = self.path + str(message['fname'])
							self.size = self.size + os.path.getsize(path)
							os.remove(path)
							print 'Delete file ' + str(message['fname'])
							prepare_mess = {}
							prepare_mess['type'] = str(DATANODE)
							prepare_mess['id'] = self.port
							prepare_mess['size'] = self.size
							length = str(len(str(prepare_mess))).rjust(4,'0')
							self.namenode.sendall(length + str(prepare_mess))
							print 'Update size to '+str(self.size)+' kb...'

	
	def accept_new_client( self ):
		newsock, (remhost, remport) = self.srvsock.accept()
		self.Clients.append(newsock)
		

	