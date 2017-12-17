# coding="utf-8"
import encrypt_layer as file_system
import socket
import sys
import json
import os
import datetime
import select
reload(sys)
sys.setdefaultencoding('utf8')
sys.path.append("../")
from defination import *

USER_PRK = None
USER_PATH = 'NONE'
USER_NAME = None
LOGIN_IN = False
USER_IP = None
SOCKET = None
ALL_SOCKET = None

EFS_DIR = '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/Client/'

def verifyargs(cmd, args, length):
	if len(args) > length:
		print 'Too many arguments for command %s.' %cmd
		print "Type 'help " + str(cmd) + "' for more information"
		return False
	elif len(args) < length:
		print 'Too few arguments for command %s.' %cmd
		print "Type 'help " + str(cmd) + "' for more information."
		return False
	return True

def execute(cmd, args):

	global USER_NAME, USER_PRK, USER_PATH, LOGIN_IN, USER_IP, SOCKET, ALL_SOCKET

	if cmd == 'help':
		dic_help = {}
		dic_help['help'] = 'print user-guide'
		dic_help['quit()'] = 'quit the efs'
		dic_help['cd'] = 'change directory (absolute/relative path are suppotred)'
		dic_help['pwd'] = 'show current absolute path'
		dic_help['ls'] = 'list all non-share files, add "-s" if you are in the "share" file directory'
		dic_help['mkdir'] = 'make a new directory (both absolute/relative path are suppotred)'
		dic_help['login'] = 'login with user name and specific private key location provided'
		dic_help['register'] = 'regist with user name and specific location to store your private key'
		dic_help['upload'] = 'upload the src file to the dest directory (both absolute/relative path are suppotred)'
		dic_help['download'] = 'download the src file to the dest directory (both absolute/relative path are suppotred)'
		dic_help['mv'] = 'move the file from src to dest (only file move is suppotred, both absolute/relative path are suppotred)'
		dic_help['rm'] = 'remove file (add "-r" to remove directory, both absolute/relative path are suppotred, recursion not suppotred)'
		dic_help['cp'] = 'copy file from src to dest (only file copy is suppotred, both absolute/relative path are suppotred)'
		dic_help['share'] = 'share file to user in mode and store private at loc (-r for read only; -w for write only; -wr for read and write)'
		dic_help['share_more1'] = 'shared files are listed in "user/share/owner/file" (location changes are not suppotred)'
		dic_help['share_more2'] = 'please share with all the members at the same time (member updates are not suppotred)'
		dic_help['share_more3'] = 'please make sure that you have yourself included in the members'
		dic_help['download-share'] = 'download share file (path listed in share directory) to loc with specific location for private keys provided'
		dic_help['upload-share'] = 'upload remote file (absolute path only) for share group with specific location for private keys provided'
		dic_help['upload-share-more'] = 'if you want to share files from the EFS, please download it first and use command "upload-share"'

		if len(args) == 0:
			print ''
			print '%10s %-50s %s' %(' ', 'help', dic_help['help']) 
			print '%10s %-50s %s' %(' ', 'quit()', dic_help['quit()'])
			print ''
			print '%10s %-50s %s' %(' ', 'cd', dic_help['cd'])
			print '%10s %-50s %s' %(' ', 'pwd', dic_help['pwd'])
			print '%10s %-50s %s' %(' ', 'ls [mode]', dic_help['ls'])
			print '%10s %-50s %s' %(' ', 'mkdir', dic_help['mkdir'])
			print '%10s %-50s %s' %(' ', 'rm [mode]', dic_help['rm'])
			print '%10s %-50s %s' %(' ', 'mv [src] [dest]', dic_help['mv'])
			print '%10s %-50s %s' %(' ', 'cp [src] [dest]', dic_help['cp'])
			print ''
			print '%10s %-50s %s' %(' ', 'register [user_name] [PRK_loc]', dic_help['register'])
			print '%10s %-50s %s' %(' ', 'login [user_name] [PRK_loc]', dic_help['login'])
			print '%10s %-50s %s' %(' ', 'upload [src] [dest]', dic_help['upload'])
			print '%10s %-50s %s' %(' ', 'download [src] [dest]', dic_help['download'])
			print ''
			print '%10s %-50s %s' %(' ', 'share [file] [mode] [user_name] [loc]...', dic_help['share'])
			print '%61s %s' %(' ', dic_help['share_more1'])
			print '%61s %s' %(' ', dic_help['share_more2'])
			print '%61s %s' %(' ', dic_help['share_more3'])
			print '%10s %-50s %s' %(' ', 'download-share [file] [RSA_1] [RSA_2] [loc]', dic_help['download-share'])
			print '%10s %-50s %s' %(' ', 'upload-share [file] [group] [RSA_1] [RSA_3]', dic_help['upload-share'])
			print '%61s %s' %(' ', dic_help['upload-share-more'])
			print ''
			return True

		else:
			try:
				c_type = dic_help[args[0]]
			except:
				print 'No command named %s.' %args[0]
				print "Type 'help' for user guide..."
				return False
			
			if args[0] == 'share':
				print ''
				print '%10s %-50s %s' %(' ', 'share [mode] [file] [user_name]', dic_help['share'])
				print '%61s %s' %(' ', dic_help['share_more1'])
				print '%61s %s' %(' ', dic_help['share_more2'])
				print '%61s %s' %(' ', dic_help['share_more3'])
				print ''
				return True

			if args[0] == 'upload-share':
				print ''
				print '%10s %-50s %s' %(' ', 'upload-share [file] [group] [RSA_1] [RSA_3]', dic_help['upload-share'])
				print '%61s %s' %(' ', dic_help['upload-share-more'])
				print ''
				return True

			print ''
			print '%10s %-60s %s' %(' ', args[0], dic_help[args[0]]) 
			print ''
			return True

	elif cmd == 'register':
		if not verifyargs(cmd, args, 2):
			return False
		elif args[1][-4:] != '.pem':
			print 'Please specify a .pem file to store private keys.'
			print "Type 'help " + str(cmd) + "' for more information."
			return False

		status, info = file_system.register(args)

		if not status:
			print 'Registration for user %s failed because %s.' %(args[0], info)
			return False
		else:
			print 'Registration for user %s succeeded.'
			print 'Your private key is stored in %s .' %args[1]
			print 'Welcome to login.'
			return True

	elif cmd == 'login':
		if not verifyargs(cmd, args, 3):
			return False
		elif args[1][-4:] != '.pem':
			print 'Please specify a .pem file to lod your private keys.'
			print "Type 'help " + str(cmd) + "' for more information."
			return False

		status, info = file_system.login(args)

		if not status:
			print 'Fail to login beacuse %s.' %info
			return False
		else:
			USER_IP = args[2]
			try:
				SOCKET = socket.socket()
				SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				SOCKET.bind(('127.0.0.1', int(USER_IP)))
				SOCKET.connect((NAMENODEHOST, NAMENODEPORT))
				#SOCKET.settimeout(5)
				print 'Login succeeded.'
			except socket.error, msg:
				print 'Open socket fail %s' % msg
				return False
			
			ALL_SOCKET = {}
			temp_socket_1 = socket.socket()
			temp_socket_1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			temp_socket_1.bind(('127.0.0.1', int(USER_IP)))
			temp_socket_1.connect((NAMENODEHOST, DataNode_1))
			ALL_SOCKET[DataNode_1] = temp_socket_1

			temp_socket_2 = socket.socket()
			temp_socket_2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			temp_socket_2.bind(('127.0.0.1', int(USER_IP)))
			temp_socket_2.connect((NAMENODEHOST, DataNode_2))
			ALL_SOCKET[DataNode_2] = temp_socket_2

			temp_socket_3 = socket.socket()
			temp_socket_3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			temp_socket_3.bind(('127.0.0.1', int(USER_IP)))
			temp_socket_3.connect((NAMENODEHOST, DataNode_3))
			ALL_SOCKET[DataNode_3] = temp_socket_3

			temp_socket_4 = socket.socket()
			temp_socket_4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			temp_socket_4.bind(('127.0.0.1', int(USER_IP)))
			temp_socket_4.connect((NAMENODEHOST, DataNode_4))
			ALL_SOCKET[DataNode_4] = temp_socket_4

			temp_socket_5 = socket.socket()
			temp_socket_5.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			temp_socket_5.bind(('127.0.0.1', int(USER_IP)))
			temp_socket_5.connect((NAMENODEHOST, DataNode_5))
			ALL_SOCKET[DataNode_5] = temp_socket_5
			
			USER_PATH = info
			USER_NAME = args[0]
			USER_PRK = args[1]
			LOGIN_IN = True

			return True

	elif cmd == 'pwd':
		if not verifyargs(cmd, args, 0):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False
		else:
			print '/' + USER_PATH
			return True

	elif cmd == 'ls':
		if len(args) == 1 and args[0] == '-s':
			if not verifyargs(cmd, args, 1):
				return False
			elif not LOGIN_IN:
				print 'Login first.'
				return False

			status, info = file_system.ls_s(USER_NAME, USER_PATH)

			if not status:
				print 'Fail to list files because %s.' %(info)
				return False

			else:
				print info
				return True

		else:
			if not verifyargs(cmd, args, 0):
				return False
			elif not LOGIN_IN:
				print 'Login first.'
				return False
			
			info = file_system.ls(USER_PATH)
			print info
			return True

	elif cmd == 'mkdir':
		if not verifyargs(cmd, args, 1):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False
		
		status, info = file_system.mkdir(USER_NAME, USER_PATH, args)
		if not status:
			print 'Fail to make new directory %s because %s.' %(args[0], info)
			return False
		else:
			print 'Make new directory %s successfully.' %args[0]
			return True

	elif cmd == 'cd':
		if not verifyargs(cmd, args, 1):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info, USER_PATH = file_system.cd(USER_NAME ,USER_PATH ,args)
		if not status:
			print 'Fail to change directory %s because %s.' %(args[0], info)
			return False
		else:
			print 'Change directory %s successfully.' %args[0]
			return True
	
	elif cmd == 'rm':
		if args[0] != '-r':
			if not verifyargs(cmd, args, 1):
				return False
			elif not LOGIN_IN:
				print 'Login first.'
				return False

			status, info = file_system.rm(USER_NAME, USER_PATH, USER_PRK , USER_IP, SOCKET, ALL_SOCKET, args)
			if not status:
				print 'Fail to remove file %s because %s.' %(args[0], info)
				return False
			else:
				print 'Remove file %s successfully.' %args[0]
				return True
		else:
			args = args[1:]
			if not verifyargs(cmd, args, 1):
				return False
			elif not LOGIN_IN:
				print 'Login first.'
				return False

			status, info = file_system.rm_r(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, args)
			if not status:
				print 'Fail to remove directory %s because %s.' %(args[0], info)
				return False
			else:
				print 'Remove directory %s successfully.' %args[0]
				return True
	
	elif cmd == 'upload':
		if not verifyargs(cmd, args, 2):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.upload(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to upload file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Upload file %s successfully.' %args[0]
			return True

	elif cmd == 'download':
		if not verifyargs(cmd, args, 2):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.download(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to download file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Download file %s successfully, already at path %s.' %(args[0], args[1])
			return True

	elif cmd == 'mv':
		'''
		mv [old_name] [new_name]
		'''
		if not verifyargs(cmd, args, 2):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.mv(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to move file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Move file %s successfully to %s .' %(args[0], args[1])
			return True

	elif cmd == 'cp':
		'''
		cp [old_name] [new_name]
		'''
		if not verifyargs(cmd, args, 2):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.cp(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to copy file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Copy file %s successfully to %s .' %(args[0], args[1])
			return True
	
	elif cmd == 'share':
		'''
		share [file] [mode] [user_name] [loc]
		'''
		if len(args) < 4:
			print 'Too few arguments for command %s.' %cmd
			return False
		elif len(args) % 3 != 1:
			print 'Not correct number of arguments for command %s.' %cmd
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		pair_user_mode = {}
		pair_user_loc = {}

		i = 1
		while i < len(args)-2:
			pair_user_mode[args[i+1]] = args[i]
			pair_user_loc[args[i+1]] = args[i+2]
			i = i + 3
		
		for i in pair_user_mode.values():
			if not (i == '-r' or i == '-w' or i == '-wr'):
				print 'No mode named %s.' %i
				print "Type 'help " + str(cmd) + "' for more information"
				return False
		
		status, info = file_system.check_share(USER_NAME, USER_PATH, args[0], pair_user_mode)

		if not status:
			print 'Fail to share file %s because %s.' %(args[0], info)
			return False 
		
		status, info = file_system.prepare_share(USER_NAME, USER_PATH, USER_PRK, args[0], pair_user_mode, pair_user_loc, USER_IP, SOCKET, ALL_SOCKET)

		if info == 'directory exsits':
			print 'Share group exsits, use "share_update" to share more files.'
			print "Type 'help share_update' for more information"
			return False

		if not status:
			print 'Fail to share file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Share file %s successfully.' %(args[0])
			print 'Please remember that your share group name is %s.' %(info)
			return True

	elif cmd == 'upload-share':
		'''
		upload-share [file] [group] [RSA_1] [RSA_3]
		'''
		if not verifyargs(cmd, args, 4):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.upload_share(USER_NAME, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to upload-share file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Upload-share file %s successfully to %s .' %(args[0], args[1])
			return True

	elif cmd == 'download-share':
		'''
		download-share [file] [RSA_1] [RSA_2] [loc]
		'''
		if not verifyargs(cmd, args, 4):
			return False
		elif not LOGIN_IN:
			print 'Login first.'
			return False

		status, info = file_system.download_share(USER_NAME, USER_IP, SOCKET, ALL_SOCKET, args)

		if not status:
			print 'Fail to download-share file %s because %s.' %(args[0], info)
			return False
		else:
			print 'Download-share file %s successfully to %s .' %(args[0], args[3])
			return True

	else:
		print 'No command named ' + str(cmd)
		print "Type 'help' for user guide."
		return True




if __name__ == '__main__':

	print 'Encrypt File System Start...'
	print "Type 'help' for user guide..."
	try:
		while True:
			try:
				show_path = USER_PATH.split('/')
				u_input = raw_input('efs/> ' + show_path[-1] + '/> ')
				cmd = u_input.split(' ')[0]
				args = u_input.split(' ')[1:]
				if cmd == 'quit()':
					print 'Quit EFS...'
					SOCKET.close()
					break
				else:
					execute(cmd, args)
			except (ValueError, KeyboardInterrupt) as e:
				print e
				continue

	except:
		print "Error Entering EFS"
	