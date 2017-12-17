import encrypt
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import base64
import os
import sys
from defination import *
import socket
import select

EFS_DIR = '/Users/mac/Desktop/Distributed-Encrypted-File-System/DEFS/Client/'
PASS = "sshpass -p 'pwd' "
SERVER = ' gaojiarui@192.168.56.101:/home/gaojiarui/myserver/'
SSH_SERVER = ' gaojiarui@192.168.56.101'
SERVER_PATH = '/home/gaojiarui/myserver/'
ILLIGAL_LOG_FILE = EFS_DIR + 'illegal_log.txt'

def _get_keys(USER_NAME, USER_PRK):
	# get user public & private key
	try:
		with open(EFS_DIR + 'user_public_RSA.json', 'r') as f:
			RSA_data = json.load(f)
	except:
		info = 'Fail to load public keys'
		return False

	public_key_loc = RSA_data[USER_NAME]

	with open(public_key_loc,'r') as f:
		USER_PK = RSA.importKey(f.read())

	with open(USER_PRK,'r') as f:
		USER_PRK = RSA.importKey(f.read())

	# get AES key
	with open(EFS_DIR + 'user_encrypt_AES.json', 'r') as f:
		AES_data = json.load(f)

	cipheraes = AES_data[USER_NAME]
	
	USER_AES = encrypt.decrypt_aes(USER_PRK, cipheraes)

	return USER_PK, USER_PRK, USER_AES

def _get_write_lock(LOCK_SOCKET, en_file_name):

	prepare_mess = {}
	prepare_mess['fname'] = str(en_file_name)
	prepare_mess['type'] = str(WRITE_LOCK)
	prepare_mess['check'] = hash(str(prepare_mess['fname'])) & 0xffff
	length = str(len(str(prepare_mess))).rjust(4,'0')
	LOCK_SOCKET.sendall(length + str(prepare_mess))
	mess = int(LOCK_SOCKET.recv(1))
	return mess

def _release_write_lock(LOCK_SOCKET, en_file_name):

	prepare_mess = {}
	prepare_mess['fname'] = str(en_file_name)
	prepare_mess['type'] = str(WRITE_RELEASE)
	prepare_mess['check'] = hash(str(prepare_mess['fname'])) & 0xffff
	length = str(len(str(prepare_mess))).rjust(4,'0')
	LOCK_SOCKET.sendall(length + str(prepare_mess))
	mess = int(LOCK_SOCKET.recv(1))
	return mess

def _get_read_lock(LOCK_SOCKET, en_file_name):

	prepare_mess = {}
	prepare_mess['fname'] = str(en_file_name)
	prepare_mess['type'] = str(READ_LOCK)
	prepare_mess['check'] = hash(str(prepare_mess['fname'])) & 0xffff
	length = str(len(str(prepare_mess))).rjust(4,'0')
	LOCK_SOCKET.sendall(length + str(prepare_mess))
	mess = int(LOCK_SOCKET.recv(1))
	return mess

def _release_read_lock(LOCK_SOCKET, en_file_name):

	prepare_mess = {}
	prepare_mess['fname'] = str(en_file_name)
	prepare_mess['type'] = str(READ_RELEASE)
	prepare_mess['check'] = hash(str(prepare_mess['fname'])) & 0xffff
	length = str(len(str(prepare_mess))).rjust(4,'0')
	LOCK_SOCKET.sendall(length + str(prepare_mess))
	mess = int(LOCK_SOCKET.recv(1))
	return mess


def _inquire(fname, SOCKET, fsize):

	prepare_mess = {}
	if int(fsize) != 0:
		prepare_mess['type'] = str(UPLOAD)
	else:
		prepare_mess['type'] = str(DOWNLOAD)
	prepare_mess['fsize'] = int(fsize)
	prepare_mess['fname'] = str(fname)
	prepare_mess['check'] = hash(str(prepare_mess['fname'])) & 0xffff
	length = str(len(str(prepare_mess))).rjust(4,'0')
	SOCKET.sendall(length + str(prepare_mess))

def _get_datanode(SOCKET):

	while True:
		rlist = [SOCKET]
		(read_list, write_list, error_list) = select.select(rlist, [], [])
		flag = 0
		for sock in read_list:
			if sock == SOCKET:
				mess = SOCKET.recv(4)
				length = int(mess[0:4])
				mess = ''
				temp = length
				while temp > 1024:
					mess = mess + sock.recv(1024)
					temp = temp - 1024
				mess = mess + sock.recv(temp)
				message = eval(mess[0:length])
				if message['check'] != hash(str(message['datanode'])) & 0xffff:
					print 'Error in getting DataNode path'
					return False
				flag = 1
				break
		if flag == 1:
			break
	
	return eval(message['datanode'])

def _delete_on_datanode(en_file_name, datanode_port, SOCKET, chunk_num):

	prepare_mess = {}
	prepare_mess['fname'] = en_file_name
	prepare_mess['type'] = str(DELETE)
	length = str(len(str(prepare_mess))).rjust(8,'0')
	SOCKET.sendall(length + str(prepare_mess))
	print 'Remove chunk %d from DataNode %d...' %(int(chunk_num), int(datanode_port))	

def _delete_on_namenode(en_file_name, SOCKET):

	prepare_mess = {}
	prepare_mess['fname'] = en_file_name
	prepare_mess['type'] = str(DELETE)
	length = str(len(str(prepare_mess))).rjust(4,'0')
	SOCKET.sendall(length + str(prepare_mess))
	print 'Remove file name from NameNode %d...' %(int(chunk_num), int(datanode_port))	

def _download_DataNode(en_file_name, datanode_port, SOCKET, chunk_num):

	prepare_mess = {}
	prepare_mess['fname'] = en_file_name
	prepare_mess['type'] = str(READ)
	length = str(len(str(prepare_mess))).rjust(8,'0')
	SOCKET.sendall(length + str(prepare_mess))
	print 'Get chunk %d from DataNode %d...' %(int(chunk_num), int(datanode_port))

	while True:
		rlist = [SOCKET]
		(read_list, write_list, error_list) = select.select(rlist, [], [])
		flag = 0
		for sock in read_list:
			if sock == SOCKET:
				mess = SOCKET.recv(8)
				length = int(mess[0:8])
				mess = ''
				temp = length
				while temp > 1024:
					mess = mess + sock.recv(1024)
					temp = temp - 1024
				mess = mess + sock.recv(temp)
				message = eval(mess[0:length])
				flag = 1
				break
		if flag == 1:
			break

	return message['content']

def _upload_DataNode(USER_IP, cipherfile, sock, chunk_num, EN_DEST_FILE, port):

	prepare_mess = {}
	prepare_mess['fname'] = EN_DEST_FILE
	prepare_mess['cipherfile'] = cipherfile
	prepare_mess['type'] = str(WRITE)
	length = str(len(str(prepare_mess))).rjust(8,'0')
	sock.sendall(length + str(prepare_mess))
	print 'Send chunk %d to DataNode %d...' %(int(chunk_num), int(port))

def register(args):
	'''
	Regist for user_name, and store the RSA private key in private_location.
	Update the "user_public_RSA.json" and "user_encrypt_AES.json"
	'''

	user_name = args[0]
	private_location = args[1]

	if user_name == 'key' or user_name[0:5] == 'group':
		info = 'invalid user name'
		return False, info

	for j in user_name:
		if j == '_':
			info = 'invalid user name'
			return False, info

	try:
		with open(EFS_DIR + 'user_public_RSA.json', 'r') as f:
			RSA_data = json.load(f)
	except:
		with open(EFS_DIR + 'user_public_RSA.json', 'w') as f:
			json.dump({}, f)
			RSA_data = {}

	try:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'r') as f:
			AES_data = json.load(f)
	except:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'w') as f:
			json.dump({}, f)
			AES_data = {}

	if user_name in RSA_data.keys():
		info = 'user name has been used'
		return False, info

	user_RSA = encrypt.generate_RSA()
	user_AES = encrypt.generate_AES()

	user_public_RSA = user_RSA.publickey()
	user_private_RSA = user_RSA
	user_encrypt_AES = encrypt.encrypt_aes(user_RSA, user_AES)
	#ttest = encrypt.decrypt_aes(user_RSA, user_encrypt_AES)
	#print ttest == user_AES

	RSA_data[user_name] = EFS_DIR + 'key/' + str(user_name) + '_RSA.pem'

	try:
		with open(RSA_data[user_name],'w') as f:
			f.write(user_public_RSA.exportKey('PEM'))
			f.close()
	except:
		info = 'fail to save public key'
		return False, info

	AES_data[user_name] = user_encrypt_AES

	#test = (base64.b64decode(AES_data[user_name]),)
	#assert(test == user_encrypt_AES)

	try:
		with open(args[1],'w') as f:
			f.write(user_RSA.exportKey('PEM'))
			f.close()
	except:
		info = 'fail to save private key'
		return False, info

	try:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'w') as g:
			json.dump(AES_data, g)
		
		with open(EFS_DIR + 'user_public_RSA.json', 'w') as f:
			json.dump(RSA_data, f)
	except:	
		info = 'fail to update keys'
		return False, info

	try:
		os.mkdir(EFS_DIR + user_name)
		os.mkdir(EFS_DIR + user_name + '/share')
		with open(EFS_DIR + user_name + '/share.json', 'w') as f:
			json.dump({}, f)
	except:
		info = 'fail to make your directory'
		return False, info

	info = 'succeed'

	return True, info


def login(args):

	'''
	User login.
	Specify user_name and location of private_key
	'''

	user_name = args[0]
	private_key_loc = args[1]

	try:
		with open(EFS_DIR + 'user_public_RSA.json', 'r') as f:
			RSA_data = json.load(f)
	except:
		info = 'Fail to load public keys'
		return False, info

	if not user_name in RSA_data.keys():
		info = 'cannot find user name'
		return False, info

	public_key_loc = RSA_data[user_name]

	with open(public_key_loc,'r') as f:
		public_key = RSA.importKey(f.read())
	with open(private_key_loc,'r') as f:
		private_key = RSA.importKey(f.read())


	if private_key.decrypt(public_key.encrypt(user_name,'')) == user_name:
		info = user_name
		return True, info
	else:
		info = 'wrong private key'
		return False, info

def ls(path):
	return os.listdir(EFS_DIR + path)

def ls_s(USER_NAME, USER_PATH):
	if USER_PATH == USER_NAME + '/share' or USER_PATH == USER_NAME + '/share/':
		with open(EFS_DIR + USER_NAME + '/' + 'share_mirror.json', 'r') as f:
			data = json.load(f)
		info = []
		for i in data.keys():
			filename_split = i.split('/')
			filename = '/'.join(filename_split[3:])
			info.append(filename)
		return True, info
	else:
		info = 'you are not in your share directory'
		return False, info

def mkdir(USER_NAME, USER_PATH, args):

	# verify command
	new_dir = args[0]

	if new_dir[-1] == '/':
		new_dir = new_dir[:-1]
	if new_dir[0:2] == './':
		new_dir = new_dir[2:]

	if new_dir[0] == '/':
		dir_path_split = new_dir.split('/')
		if USER_NAME != dir_path_split[1]:
			info = 'file permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'mkdir ' + new_dir)
			return False, info
		else:
			dir_name = EFS_DIR + new_dir[1:]
	else:
		dir_name = EFS_DIR + USER_PATH + '/' + new_dir
		
	if os.path.isdir(dir_name):
		info = 'directory already exsits'
		return False, info

	os.mkdir(dir_name)
	info = 'succeed'
	return True, info

def cd(user, path, args):
	new_path = args[0]
	if new_path[-1] == '/':
		new_path = new_path[:-1]
	if new_path[0:2] == './':
		new_path = new_path[2:]
	if new_path[0] == '/':
		user_path = new_path.split('/')
		if user_path[1] != user:
			info = 'permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + user + ':' + 'cd ' + user_path)
			return False, info, path
		else:
			if os.path.isdir(EFS_DIR + new_path[1:]):
				info = 'succeed'
				return True, info, new_path[1:]
			else:
				info = 'no such directory'
				return False, info, path
	elif new_path == '..':
		if path == user:
			info = 'permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + user + ':' + 'cd ' + user_path)
			return False, info, path
		else:
			path = path.split('/')
			change_path = '/'.join(path[:-1])
			info = 'succeed'
			return True, info, change_path
	else:
		if os.path.isdir(EFS_DIR + path + '/' + new_path):
			info = 'succeed'
			return True, info, path + '/' + new_path
		else:
			info = 'no such directory'
			return False, info, path

def rm(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	# verify command
	rm_file = args[0]

	if rm_file[-1] == '/':
		info = 'this is not a file'
		return False, info
	if rm_file[0:2] == './':
		rm_file = rm_file[2:]

	if rm_file[0] == '/':
		rm_path_split = rm_file.split('/')
		if USER_NAME != rm_path_split[1]:
			info = 'file permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'rm ' + rm_file)
			return False, info
		else:
			rm_path = EFS_DIR + rm_file[1:]
	else:
		rm_path = EFS_DIR + USER_PATH + '/' + rm_file
		
	if not os.path.isfile(rm_path):
		info = 'no such file'
		return False, info
	

	if rm_path == EFS_DIR + USER_NAME + '/' + 'share.json' or rm_path == EFS_DIR + USER_NAME + '/' + 'share_mirror.json':
		info = 'permission denied'
		with open(ILLIGAL_LOG_FILE, 'a') as f:
			f.write('\n' + USER_NAME + ':' + 'rm ' + rm_path)
		return False, info
	if not os.path.isfile(rm_path):
		info = 'no such file'
		return False, info

	try:
		USER_PK, USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info

	# get encrypted file name
	en_file_name = encrypt.encrypt_filename(USER_PK, rm_path)
	en_file_name = en_file_name.replace("/",r"_")[0:100]

	try:
		#os.system(PASS + ' ssh ' + SSH_SERVER + ' rm ' + SERVER_PATH + en_file_name)

		_inquire(en_file_name, SOCKET, 0)
		
		DataNode = _get_datanode(SOCKET)
		
		while _get_write_lock(LOCK_SOCKET, en_file_name) == 0:
			pass

		for i in DataNode.keys():
			for j in DataNode[i]:
				_delete_on_datanode(en_file_name+'_'+str(i), j, ALL_SOCKET[j], int(i))
			
		_release_write_lock(LOCK_SOCKET, en_file_name)

		_delete_on_namenode(en_file_name, SOCKET)

	except:
		info = 'error in removing file from the server'
		return False, info

	os.remove(rm_path)
	info = 'succeed'
	return True, info
	

def rm_r(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	rm_dir = args[0]

	if rm_dir[0:2] == './':
		rm_dir = rm_dir[2:]

	if rm_dir[0] == '/':
		rm_dir_split = rm_dir.split('/')
		if USER_NAME != rm_dir_split[1]:
			info = 'directory permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'rm -r ' + rm_dir)
			return False, info
		else:
			rm_path = EFS_DIR + rm_dir[1:]
	else:
		rm_path = EFS_DIR + USER_PATH + '/' + rm_dir
		
	if not os.path.isdir(rm_path):
		info = 'no such file'
		return False, info

	
	for parent,dirnames,filenames in os.walk(rm_path):
		for filename in filenames:
			rm(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [os.path.join(parent,filename)])
			os.remove(os.path.join(parent,filename))
		

	if os.path.isdir(rm_path):
		try:
			os.rmdir(rm_path)
			info = 'succeed'
			return True, info
		except:
			info = 'recursion not supported'
			return False, info
	else:
		info = 'no such directory'
		return False, info

def upload(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	# verify command
	SOURCE = args[0]
	dest = args[1]
	if dest[-1] == '/':
		dest = dest[:-1]
	if dest[0:2] == './':
		dest = dest[2:]

	if not os.path.isfile(SOURCE):
		info = 'no such source file'
		return False, info
	if dest[0] == '/':
		dest_path_split = dest.split('/')
		if USER_NAME != dest_path_split[1]:
			info = 'destination directory permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + user + ':' + 'upload ' + dest)
			return False, info
		else:
			DEST = EFS_DIR + dest[1:]
	else:
		DEST = EFS_DIR + USER_PATH + '/' + dest

	if not os.path.isdir(DEST):
		info = 'no such destination directory'
		return False, info

	try:
		USER_PK, USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info
	
	try:
		# get encrypted file name
		source_split = SOURCE.split('/')
		filename = source_split[-1]
		DEST_FILE = DEST + '/' + filename
		
		en_file_name = encrypt.encrypt_filename(USER_PK, DEST_FILE)
		en_file_name = en_file_name.replace("/",r"_")[0:100]

		# encrypt file content
		cipherfile = encrypt.encrypt_file(USER_AES, SOURCE)

		# sign the hash value of the file
		signature = encrypt.sign_file(USER_PRK, cipherfile)
		# len(signature) = 344

		cipherfile = signature + cipherfile
		
		# backup in the file system
		EN_DEST_FILE = DEST + '/' + en_file_name
		with open(EN_DEST_FILE, 'w') as f:
			f.write(cipherfile)

		# test: try to decrypt
		# plain = encrypt.decrypt_file(USER_AES, DEST_FILE)
		# with open(DEST_FILE, 'w') as f:
		# 	f.write(plain)

		# inquire on namenode
		
		_inquire(en_file_name, SOCKET, len(cipherfile))
		
		DataNode = _get_datanode(SOCKET)

		#_upload_DataNode(USER_IP, cipherfile[0:16384], DataNode_1, 1, en_file_name)
		
		# get lock
		while _get_write_lock(LOCK_SOCKET, en_file_name) == 0:
			pass

		for i in DataNode.keys():
			for j in DataNode[i]:
				if int(i) != len(cipherfile) / 16384 + 1:
					_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:int(i)*16384], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))
				else:
					_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:len(cipherfile)], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))			
		
		_release_write_lock(LOCK_SOCKET, en_file_name)

		# upload to the datanode
		# os.system(PASS + 'scp ' + EN_DEST_FILE + SERVER)
		os.rename(EN_DEST_FILE, DEST_FILE)
	except:
		info = 'error in uploading'
		return False, info

	info = 'succeed'
	return True, info

def download(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	#verigy command
	source = args[0]
	save_pos = args[1]

	if source[-1] == '/':
		source = source[:-1]
	if source[0:2] == './':
		source = source[2:]

	if not os.path.isdir(save_pos):
		info = 'no such destination directory'
		return False, info
	if source[0] == '/':
		source_path_split = source.split('/')
		if USER_NAME != source_path_split[1]:
			info = 'source directory permission denied'
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'download ' + source)
			return False, info
		else:
			source_file = EFS_DIR + source[1:]
	else:
		source_file = EFS_DIR + USER_PATH + '/' + source
		
	if not os.path.isfile(source_file):
		info = 'no such source file'
		return False, info
	_USER_PRK = USER_PRK
	try:
		USER_PK, USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info
	
	try:
		# get encrypted name
		en_file_name = encrypt.encrypt_filename(USER_PK, source_file)
		en_file_name = en_file_name.replace("/",r"_")[0:100]
		
		# download file
		#os.system(PASS + 'scp ' + SERVER + en_file_name + ' ' + save_pos)
		_inquire(en_file_name, SOCKET, 0)
		
		DataNode = _get_datanode(SOCKET)

		#_upload_DataNode(USER_IP, cipherfile[0:16384], DataNode_1, 1, en_file_name)
		
		while _get_read_lock(LOCK_SOCKET, en_file_name) == 0:
			pass

		i = 1
		cipherfile = ''
		while DataNode.has_key(str(i)):
			datanode_port = int(DataNode[str(i)][0])
			data = str(_download_DataNode(en_file_name+'_'+str(i), datanode_port, ALL_SOCKET[datanode_port], int(i)))
			cipherfile = cipherfile + data
			i = i + 1
				# if int(i) != len(cipherfile) / 16384 + 1:
				# 	_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:int(i)*16384], ALL_SOCKET[j], int(i), en_file_name+'_'+str(i), j)
				# else:
				# 	_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:len(cipherfile)], ALL_SOCKET[j], int(i), en_file_name+'_'+str(i), j)			
		
		_release_read_lock(LOCK_SOCKET, en_file_name)

		source_split = source.split('/')
		filename = source_split[-1]

		# os.rename(save_pos + '/' + en_file_name, save_pos + '/' + filename)
		with open(save_pos + '/' + filename, 'wb') as f:
			f.write(cipherfile)

	except:
		info = 'download error'
		return False, info

	# with open(save_pos + '/' + filename, 'r') as f:
	# 	cipherfile = f.read()

	signature = cipherfile[0:344]
	cipherfile = cipherfile[344:]

	with open(save_pos + '/' + filename, 'w') as f:
		f.write(cipherfile)

	verify = encrypt.verify_sign(USER_PRK, signature, cipherfile)

	if not verify:
		info = 'the file has been modified illegally'
		os.remove(save_pos + '/' + filename)
		try:
			source_path = source_split[:-1]
			en_source = EFS_DIR + '/'.join(source_path) + '/' + en_file_name
			os.rename(source_file, en_source)
			#os.system(PASS + 'scp ' + en_source + SERVER)
			
			with open(en_source, 'w') as f:
				cipherfile = f.read()
		
			_inquire(en_file_name, SOCKET, len(cipherfile))
		
			DataNode = _get_datanode(SOCKET)
		
			while _get_write_lock(LOCK_SOCKET, en_file_name) == 0:
				pass

			for i in DataNode.keys():
				for j in DataNode[i]:
					if int(i) != len(cipherfile) / 16384 + 1:
						_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:int(i)*16384], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))
					else:
						_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:len(cipherfile)], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))			
			
			_release_write_lock(LOCK_SOCKET, en_file_name)

			os.rename(en_source, source_file)
			info = 'and the backup file has been uploaded, please read again'
			return False, info
		except:
			info = 'and fail to upload the backup file'
			return False, info
	
	else:
		try:
			# update backup
			with open(save_pos + '/' + filename, 'r') as f:
				cipherfile = f.read()
			with open(source_file, 'w') as f:
				f.write(cipherfile)

			plain = encrypt.decrypt_file(USER_AES, save_pos + '/' + filename)
			with open(save_pos + '/' + filename, 'w') as f:
				f.write(plain)
			info = 'succeed'
			return True, info
		except:
			info = 'decrypt error'
			return False, info

def mv(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	old_name = args[0]
	new_name = args[1]

	# verify old name
	if old_name[-1] == '/':
		old_name = old_name[:-1]
	if old_name[0:2] == './':
		old_name = old_name[2:]

	if old_name[0] == '/':
		old_name_split = old_name.split('/')
		if USER_NAME != old_name_split[1]:
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'mv ' + old_name)
			info = 'file permission denied'
			return False, info
		else:
			old_file = EFS_DIR + old_name[1:]
	else:
		old_file = EFS_DIR + USER_PATH + '/' + old_name
		
	if not os.path.isfile(old_file):
		info = 'no such file'
		return False, info

	# verify new name
	if new_name[-1] == '/':
		old_file_name = old_file.split('/')
		new_name = new_name + old_file_name[-1]
	if new_name[0:2] == './':
		new_name = new_name[2:]

	if new_name[0] == '/':
		new_name_split = new_name.split('/')
		if USER_NAME != new_name_split[1]:
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'mv ' + new_name)
			info = 'file permission denied'
			return False, info
		else:
			new_file = EFS_DIR + new_name[1:]
	else:
		new_file = EFS_DIR + USER_PATH + '/' + new_name

	try:
		USER_PK, _USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info

	#os.system(" sshpass -p 'gjr950614' ssh gaojiarui@192.168.56.101 rm /home/gaojiarui/myserver/test.txt")
	try:
		# get encrypted name
		# en_old_file_name = encrypt.encrypt_filename(USER_PK, old_file)
		# en_old_file_name = en_old_file_name.replace("/",r"_")[0:100]
		# en_new_file_name = encrypt.encrypt_filename(USER_PK, new_file)
		# en_new_file_name = en_new_file_name.replace("/",r"_")[0:100]
		download(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [args[0], '/Users/mac/Desktop'])
		rm(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [old_name])
		new_split = new_name.split('/')
		new_filename = new_split[-1]
		old_split = old_name.split('/')
		old_filename = old_split[-1]
		os.rename('/Users/mac/Desktop/'+old_filename, '/Users/mac/Desktop/'+new_filename)
		upload(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKETs, ['/Users/mac/Desktop/'+new_filename, '/'.join(new_split[0:len(new_split)-1])])
		#os.system(PASS + 'ssh ' + SSH_SERVER + ' mv ' + SERVER_PATH + en_old_file_name + ' ' + SERVER_PATH + en_new_file_name)
		os.remove('/Users/mac/Desktop/'+new_filename)
		os.rename(old_file, new_file)
	except:
		info = 'cannot move file on the server'
		return False, info

	info = 'succeed'
	return True, info

def cp(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	old_name = args[0]
	new_name = args[1]

	# verify old name
	if old_name[-1] == '/':
		old_name = old_name[:-1]
	if old_name[0:2] == './':
		old_name = old_name[2:]

	if old_name[0] == '/':
		old_name_split = old_name.split('/')
		if USER_NAME != old_name_split[1]:
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'cp ' + old_name)
			info = 'file permission denied'
			return False, info
		else:
			old_file = EFS_DIR + old_name[1:]
	else:
		old_file = EFS_DIR + USER_PATH + '/' + old_name
		
	if not os.path.isfile(old_file):
		info = 'no such file'
		return False, info

	# verify new name
	if new_name[-1] == '/':
		old_file_name = old_file.split('/')
		new_name = new_name + old_file_name[-1]
	if new_name[0:2] == './':
		new_name = new_name[2:]

	if new_name[0] == '/':
		new_name_split = new_name.split('/')
		if USER_NAME != new_name_split[1]:
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'cp ' + new_name)
			info = 'file permission denied'
			return False, info
		else:
			new_file = EFS_DIR + new_name[1:]
	else:
		new_file = EFS_DIR + USER_PATH + '/' + new_name

	try:
		USER_PK, _USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info

	#os.system(" sshpass -p 'gjr950614' ssh gaojiarui@192.168.56.101 rm /home/gaojiarui/myserver/test.txt")
	try:
		# get encrypted name
		# en_old_file_name = encrypt.encrypt_filename(USER_PK, old_file)
		# en_old_file_name = en_old_file_name.replace("/",r"_")[0:100]
		# en_new_file_name = encrypt.encrypt_filename(USER_PK, new_file)
		# en_new_file_name = en_new_file_name.replace("/",r"_")[0:100]

		download(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [args[0], '/Users/mac/Desktop'])
		new_split = new_name.split('/')
		new_filename = new_split[-1]
		old_split = old_name.split('/')
		old_filename = old_split[-1]
		os.rename('/Users/mac/Desktop/'+old_filename, '/Users/mac/Desktop/'+new_filename)
		upload(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, ['/Users/mac/Desktop/'+new_filename, '/'.join(new_split[0:len(new_split)-1])])
		#os.system(PASS + 'ssh ' + SSH_SERVER + ' mv ' + SERVER_PATH + en_old_file_name + ' ' + SERVER_PATH + en_new_file_name)
		os.remove('/Users/mac/Desktop/'+new_filename)
	except:
		info = 'cannot copy file to the server'
		return False, info

	info = 'succeed'
	return True, info

def check_share(USER_NAME, USER_PATH, source, pair):
	
	# verify source
	if source[0:2] == './':
		source = source[2:]

	if source[0] == '/':
		source_split = source.split('/')
		if USER_NAME != source_split[1]:
			with open(ILLIGAL_LOG_FILE, 'a') as f:
				f.write('\n' + USER_NAME + ':' + 'share ' + source)
			info = 'file permission denied'
			return False, info
		else:
			source_file = EFS_DIR + source[1:]
	else:
		source_file = EFS_DIR + USER_PATH + '/' + source
		
	if not os.path.isfile(source_file):
		info = 'no such file'
		return False, info

	# verify user
	try:
		with open(EFS_DIR + 'user_public_RSA.json', 'r') as f:
			RSA_data = json.load(f)
	except:
		info = 'Fail to load public keys'
		return False
	
	for i in pair.keys():
		if i not in RSA_data.keys() or i == USER_NAME:
			info = 'invalid user name ' + str(i) 
			return False, info

	info = 'succeed'
	return True, info

def prepare_share(USER_NAME, USER_PATH, USER_PRK, source, pair_user_mode, pair_user_loc, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET):

	share_user = pair_user_mode.keys()
	share_file = '_'.join(share_user)

	if os.path.isdir(EFS_DIR + share_file):
		info = 'directory exsits'
		return False, info

	try:
		share_RSA_1 = encrypt.generate_RSA()
		share_RSA_2 = encrypt.generate_RSA()
		share_RSA_3 = encrypt.generate_RSA()
		share_AES = encrypt.generate_AES()
	except:
		info = 'error generate keys'
		return False, info

	try:
		with open(EFS_DIR + 'share_public_RSA.json', 'r') as f:
			share_RSA_data = json.load(f)
	except:
		with open(EFS_DIR + 'share_public_RSA.json', 'w') as f:
			json.dump({}, f)
			share_RSA_data = {}

	try:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'r') as f:
			AES_data = json.load(f)
	except:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'w') as f:
			json.dump({}, f)
			AES_data = {}

	share_public_RSA_1 = share_RSA_1.publickey()
	share_public_RSA_2 = share_RSA_2.publickey()
	share_public_RSA_3 = share_RSA_3.publickey()
	share_encrypt_AES = encrypt.encrypt_aes(share_RSA_2, share_AES)
	
	share_RSA = {}
	share_RSA['RSA_1'] = EFS_DIR + 'key/' + str(share_file) + '_RSA_1.pem'
	share_RSA['RSA_2'] = EFS_DIR + 'key/' + str(share_file) + '_RSA_2.pem'
	share_RSA['RSA_3'] = EFS_DIR + 'key/' + str(share_file) + '_RSA_3.pem'
	share_RSA_data[share_file] = share_RSA

	try:
		with open(share_RSA['RSA_1'],'w') as f:
			f.write(share_public_RSA_1.exportKey('PEM'))
			f.close()
		with open(share_RSA['RSA_2'],'w') as f:
			f.write(share_public_RSA_2.exportKey('PEM'))
			f.close()
		with open(share_RSA['RSA_3'],'w') as f:
			f.write(share_public_RSA_3.exportKey('PEM'))
			f.close()
	except:
		info = 'fail to save public key'
		return False, info

	AES_data[share_file] = share_encrypt_AES

	try:
		with open(EFS_DIR + 'user_encrypt_AES.json', 'w') as g:
			json.dump(AES_data, g)
		
		with open(EFS_DIR + 'share_public_RSA.json', 'w') as f:
			json.dump(share_RSA_data, f)
	except:	
		info = 'fail to update keys'
		return False, info

	# store keys for members
	# read: rsa_1 rsa_2
	# write: rsa_1 rsa_3
	# read & write: rsa_1 rsa_2 rsa_3

	for i in pair_user_mode.keys():
		mode = pair_user_mode[i]
		loc = pair_user_loc[i]
		if loc[-1] != '/':
			loc = loc + '/'
		if not os.path.isdir(loc):
			info = 'fail to save private key for ' + str(i) + ' at ' + str(loc)
			return False, info
		if mode == '-r':
			try:
				with open(loc + share_file + '_RSA_1.pem','w') as f:
					f.write(share_RSA_1.exportKey('PEM'))
					f.close()
				with open(loc + share_file + '_RSA_2.pem','w') as f:
					f.write(share_RSA_2.exportKey('PEM'))
					f.close()
			except:
				info = 'fail to save private key for ' + str(i) + ' at ' + str(loc)
				return False, info
		elif mode == '-w':
			try:
				with open(loc + share_file + '_RSA_1.pem','w') as f:
					f.write(share_RSA_1.exportKey('PEM'))
					f.close()
				with open(loc + share_file + '_RSA_3.pem','w') as f:
					f.write(share_RSA_3.exportKey('PEM'))
					f.close()
			except:
				info = 'fail to save private key for ' + str(i) + ' at ' + str(loc)
				return False, info
		else:
			try:
				with open(loc + share_file + '_RSA_1.pem','w') as f:
					f.write(share_RSA_1.exportKey('PEM'))
					f.close()
				with open(loc + share_file + '_RSA_2.pem','w') as f:
					f.write(share_RSA_2.exportKey('PEM'))
					f.close()
				with open(loc + share_file + '_RSA_3.pem','w') as f:
					f.write(share_RSA_3.exportKey('PEM'))
					f.close()
			except:
				info = 'fail to save private key for ' + str(i) + ' at ' + str(loc)
				return False, info


	if source[0] == '/':
		source_split = source.split('/')
		if USER_NAME != source_split[1]:
			info = 'file permission denied'
			return False, info
		else:
			source_file = EFS_DIR + source[1:]
	else:
		source_file = EFS_DIR + USER_PATH + '/' + source

	source_split = source_file.split('/')
	filename = source_split[-1]

	# update all share file lists
	for i in pair_user_loc:
		user_path = EFS_DIR + i + '/'
		with open(user_path + 'share_mirror.json', 'r') as f:
			data = json.load(f)
		data['/' + i + '/share/' + USER_NAME + '/' + filename] = '/' + share_file + '/' + filename
		with open(user_path + 'share_mirror.json', 'w') as f:
			json.dump(data, f)

	try:
		USER_PK, _USER_PRK, USER_AES = _get_keys(USER_NAME, USER_PRK)
	except:
		info = 'get keys error'
		return False, info

	try:
		# get encrypted name
		# dest_file = EFS_DIR + share_file + '/' + filename
		# en_source_file_name = encrypt.encrypt_filename(USER_PK, source_file)
		# en_source_file_name = en_source_file_name.replace("/",r"_")[0:100]
		# en_share_file_name = encrypt.encrypt_filename(USER_PK, dest_file)
		# en_share_file_name = en_share_file_name.replace("/",r"_")[0:100]

		download(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [source, '/Users/mac/Desktop'])
		rm(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, [filename])
		upload(USER_NAME, USER_PATH, USER_PRK, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, ['/Users/mac/Desktop/'+filename, share_file])
		#os.system(PASS + 'ssh ' + SSH_SERVER + ' mv ' + SERVER_PATH + en_old_file_name + ' ' + SERVER_PATH + en_new_file_name)
		os.remove('/Users/mac/Desktop/'+filename)
		#os.rename(old_file, new_file)
		
		#os.system(PASS + 'ssh ' + SSH_SERVER + ' mv ' + SERVER_PATH + en_source_file_name + ' ' + SERVER_PATH + en_share_file_name)
	except:
		info = 'cannot move file on the server'
		return False, info

	try:
		dest_file = EFS_DIR + share_file + '/' + filename
		os.mkdir(EFS_DIR + share_file)
		os.rename(source_file, dest_file)
	except:
		info = 'unable to make new share directory'
		return False, info

	info = share_file
	return True, info

def upload_share(USER_NAME, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):

	file_path = args[0]
	group_name = args[1]
	loc_RSA_1 = args[2]
	loc_RSA_3 = args[3]

	if not os.path.isfile(file_path):
		info = 'no such file'
		return False, info

	if file_path[0] != '/':
		info = 'absolute file path only'
		return False, info

	with open(loc_RSA_1,'r') as f:
		SHARE_RSA_1 = RSA.importKey(f.read())

	with open(loc_RSA_3,'r') as f:
		SHARE_RSA_3 = RSA.importKey(f.read())
	
	with open(EFS_DIR + '/key/' + group_name + '_RSA_1.pem', 'r') as f:
		SHARE_PUBLIC_RSA_1 = RSA.importKey(f.read())
	with open(EFS_DIR + '/key/' + group_name + '_RSA_2.pem', 'r') as f:
		SHARE_PUBLIC_RSA_2 = RSA.importKey(f.read())
	with open(EFS_DIR + '/key/' + group_name + '_RSA_3.pem', 'r') as f:
		SHARE_PUBLIC_RSA_3 = RSA.importKey(f.read())

	split_file_path = file_path.split('/')
	filename = split_file_path[-1]
	share_path = EFS_DIR + group_name + '/' + filename

	if not SHARE_RSA_1.decrypt(SHARE_PUBLIC_RSA_1.encrypt(USER_NAME,'')) == USER_NAME:
		with open(ILLIGAL_LOG_FILE, 'a') as f:
			f.write('\n' + USER_NAME + ':' + 'upload-share RSA_1 ' + file_path)
		info = 'invalid RSA_1'
		return False, info
	if not SHARE_RSA_3.decrypt(SHARE_PUBLIC_RSA_3.encrypt(USER_NAME,'')) == USER_NAME:
		with open(ILLIGAL_LOG_FILE, 'a') as f:
			f.write('\n' + USER_NAME + ':' + 'upload-share RSA_3 ' + file_path)
		info = 'invalid RSA_3'
		return False, info
	
	with open(file_path, 'r') as f:
		data = f.read()
	with open(share_path, 'w') as f:
		f.write(data)

	# new AES key
	SHARE_AES = encrypt.generate_AES()
	EN_SHARE_AES = encrypt.encrypt_aes(SHARE_PUBLIC_RSA_2, SHARE_AES)

	with open(EFS_DIR + 'user_encrypt_AES.json', 'r') as f:
		AES_data = json.load(f)
	AES_data[group_name] = EN_SHARE_AES
	with open(EFS_DIR + 'user_encrypt_AES.json', 'w') as f:
		json.dump(AES_data, f)

	# encrypt filename
	en_share_path = encrypt.encrypt_filename(SHARE_RSA_1, share_path)
	en_share_path = en_share_path.replace("/",r"_")[0:100]

	# encrypt file content
	cipherfile = encrypt.encrypt_file(SHARE_AES, share_path)

	# sign the hash value of the file
	signature = encrypt.sign_file(SHARE_RSA_3, cipherfile)
	# len(signature) = 344

	cipherfile = signature + cipherfile

	with open(EFS_DIR + group_name + '/' + en_share_path, 'w') as f:
		f.write(cipherfile)

	_inquire(en_share_path, SOCKET, len(cipherfile))
		
	DataNode = _get_datanode(SOCKET)

	while _get_write_lock(LOCK_SOCKET, en_share_path) == 0:
		pass
		
	for i in DataNode.keys():
		for j in DataNode[i]:
			if int(i) != len(cipherfile) / 16384 + 1:
				_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:int(i)*16384], ALL_SOCKET[int(j)], int(i), en_share_path+'_'+str(i), int(j))
			else:
				_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:len(cipherfile)], ALL_SOCKET[int(j)], int(i), en_share_path+'_'+str(i), int(j))			
		
	_release_write_lock(LOCK_SOCKET, en_share_path)
	#os.system(PASS + 'scp ' + EFS_DIR + group_name + '/' + en_share_path + ' ' + SERVER)
	os.rename(EFS_DIR + group_name + '/' + en_share_path, share_path)

	member = group_name.split('_')
	for i in member:
		user_path = EFS_DIR + i + '/'
		with open(user_path + 'share_mirror.json', 'r') as f:
			data = json.load(f)
		data['/' + i + '/share/' + USER_NAME + '/' + filename] = '/' + group_name + '/' + filename
		with open(user_path + 'share_mirror.json', 'w') as f:
			json.dump(data, f)

	info = 'succeed'
	return True, info

def download_share(USER_NAME, USER_IP, SOCKET, ALL_SOCKET, LOCK_SOCKET, args):
	file_path = args[0]
	loc_RSA_1 = args[1]
	loc_RSA_2 = args[2]
	save_pos = args[3]

	if file_path[0] == '/':
		info = 'file name should be one of the listed results in "ls -s" in user/share/'
		return False, info

	share_path = '/' + USER_NAME + '/share/' + file_path

	with open(EFS_DIR + USER_NAME + '/share_mirror.json', 'r') as f:
		data = json.load(f)

	if share_path not in data.keys():
		info = 'file name should be one of the listed results in "ls -s" in user/share/'
		return False, info
	
	share_mirror = data[share_path]
	group_name = share_mirror.split('/')
	filename = group_name[-1]
	group_name = group_name[1]
	real_path = EFS_DIR + str(share_mirror[1:])
	
	with open(loc_RSA_1,'r') as f:
		SHARE_RSA_1 = RSA.importKey(f.read())

	with open(loc_RSA_2,'r') as f:
		SHARE_RSA_2 = RSA.importKey(f.read())
	
	with open(EFS_DIR + '/key/' + group_name + '_RSA_1.pem', 'r') as f:
		SHARE_PUBLIC_RSA_1 = RSA.importKey(f.read())
	with open(EFS_DIR + '/key/' + group_name + '_RSA_2.pem', 'r') as f:
		SHARE_PUBLIC_RSA_2 = RSA.importKey(f.read())
	with open(EFS_DIR + '/key/' + group_name + '_RSA_3.pem', 'r') as f:
		SHARE_PUBLIC_RSA_3 = RSA.importKey(f.read())

	if not SHARE_RSA_1.decrypt(SHARE_PUBLIC_RSA_1.encrypt(USER_NAME,'')) == USER_NAME:
		with open(ILLIGAL_LOG_FILE, 'a') as f:
			f.write('\n' + USER_NAME + ':' + 'download-share RSA_1 ' + file_path)
		info = 'invalid RSA_1'
		return False, info
	if not SHARE_RSA_2.decrypt(SHARE_PUBLIC_RSA_2.encrypt(USER_NAME,'')) == USER_NAME:
		with open(ILLIGAL_LOG_FILE, 'a') as f:
			f.write('\n' + USER_NAME + ':' + 'download-share RSA_ ' + file_path)
		info = 'invalid RSA_2'
		return False, info

	# get AES key
	with open(EFS_DIR + 'user_encrypt_AES.json', 'r') as f:
		AES_data = json.load(f)
	cipheraes = AES_data[group_name]
	SHARE_AES = encrypt.decrypt_aes(SHARE_RSA_2, cipheraes)

	en_file_name = encrypt.encrypt_filename(SHARE_RSA_1, real_path)
	en_file_name = en_file_name.replace("/",r"_")[0:100]
		
	# download file
	#os.system(PASS + 'scp ' + SERVER + en_file_name + ' ' + save_pos)
	_inquire(en_file_name, SOCKET, 0)
		
	DataNode = _get_datanode(SOCKET)

	#_upload_DataNode(USER_IP, cipherfile[0:16384], DataNode_1, 1, en_file_name)
	
	while _get_read_lock(LOCK_SOCKET, en_file_name) == 0:
		pass

	i = 1
	cipherfile = ''
	while DataNode.has_key(str(i)):
		datanode_port = int(DataNode[str(i)][0])
		data = str(_download_DataNode(en_file_name+'_'+str(i), datanode_port, ALL_SOCKET[datanode_port], int(i)))
		cipherfile = cipherfile + data
		i = i + 1

	_release_read_lock(LOCK_SOCKET, en_file_name)

	# os.rename(save_pos + '/' + en_file_name, save_pos + '/' + filename)
	#os.rename(save_pos + '/' + en_file_name, save_pos + '/' + filename)

	signature = cipherfile[0:344]
	cipherfile = cipherfile[344:]

	with open(save_pos + '/' + filename, 'w') as f:
		f.write(cipherfile)

	verify = encrypt.verify_sign(SHARE_PUBLIC_RSA_3, signature, cipherfile)

	if not verify:
		info = 'the file has been modified illegally'
		os.remove(save_pos + '/' + filename)
		try:
			split_real_path = real_path.split('/')
			split_real_path = split_real_path[:-1]
			en_source = '/'.join(split_real_path) + '/' + en_file_name
			os.rename(real_path, en_source)
			#os.system(PASS + 'scp ' + en_source + SERVER)
			with open(en_source, 'w') as f:
				cipherfile = f.read()
		
			_inquire(en_file_name, SOCKET, len(cipherfile))
		
			DataNode = _get_datanode(SOCKET)
		
			while _get_write_lock(LOCK_SOCKET, en_file_name) == 0:
				pass

			for i in DataNode.keys():
				for j in DataNode[i]:
					if int(i) != len(cipherfile) / 16384 + 1:
						_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:int(i)*16384], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))
					else:
						_upload_DataNode(USER_IP, cipherfile[(int(i)-1)*16384:len(cipherfile)], ALL_SOCKET[int(j)], int(i), en_file_name+'_'+str(i), int(j))			
		
			_release_write_lock(LOCK_SOCKET, en_file_name)
			os.rename(en_source, real_path)
			info = info + ' and the backup file has been uploaded, please download again'
			return False, info
		except:
			info = info + ' and fail to upload the backup file'
			return False, info
	
	else:
		try:
			# update backup
			with open(save_pos + '/' + filename, 'r') as f:
				cipherfile = f.read()
			with open(real_path, 'w') as f:
				f.write(cipherfile)

			plain = encrypt.decrypt_file(SHARE_AES, save_pos + '/' + filename)
			with open(save_pos + '/' + filename, 'w') as f:
				f.write(plain)
			info = 'succeed'
			return True, info
		except:
			info = 'decrypt error'
			return False, info
	
	info = 'succeed'
	return True, info


if __name__ == '__main__':
	#_get_keys('test', '/Users/mac/Desktop/test.pem')
	#register(['miao2', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/miao2.pem']);
	#register(['hey', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/hey.pem'])
	#login(['kitten', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/kitten.pem']);
	#mkdir('kitten',['dic1'])
	#rm_r('miao', 'miao',['dic2'])
	#status, info = rm('hey', 'hey', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/hey.pem', ['/hey/dic1/2.png'])
	status, info = upload('test', 'test', '/Users/mac/Desktop/test.pem', ['/Users/mac/Desktop/1.png', 'dict1'])
	#read('hey', 'hey', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/hey.pem', ['/hey/dic1/1.png', '/Users/mac/Desktop'])
	#status, info = mv('hey', 'hey', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/hey.pem', ['/hey/dic1/1.png', '/hey/dic1/2.png'])
	#status, info = check_share('kitten', 'kitten', 'dic1/1.png', {'bi': '-r', 'gibh': '-wr', 'vihbk': '-w'})
	#status, info = prepare_share('kitten', 'kitten', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/kitten.pem', 'dic1/1.png', {'miao': '-r', 'hey': '-w', 'kitten': '-wr'}, {'miao': '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/read', 'hey': '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/write', 'kitten': '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/read-write'})
	#status, info = ls_s('kitten', 'kitten/share')
	#status, info = upload_share('miao', ['/Users/mac/Desktop/2.png', 'miao_hey_kitten', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/write/miao_hey_kitten_RSA_1.pem', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/write/miao_hey_kitten_RSA_3.pem'])
	#status, info = download_share('miao', ['miao/2.png', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/read/miao_hey_kitten_RSA_1.pem', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/test-share/read/miao_hey_kitten_RSA_2.pem','/Users/mac/Desktop/temp/'])
	#status, info = cp('hey', 'hey', '/Users/mac/Desktop/system_security/pj/Encryped-file-system/src/hey.pem', ['/hey/dic1/1.png', '/hey/dic1/1.png'])
	print info
	pass
