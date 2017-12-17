import json
import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Signature import PKCS1_PSS

# function chunk_size() is coppied from https://github.com/henchill/encrypted_file_system
def chunk_size(key):
	"""Returns the maximum PKCS1_OAEP encryption length.

	This is the size of the RSA modulus (N) in bytes, minus two
	times the digest (SHA-1) size, minus 2.
	"""

	return (key.size() / 8) - (2 * SHA.digest_size) - 2 - 10

def generate_RSA():
	key = RSA.generate(2048)
	return key

def generate_AES():
	key = Random.new().read(32)
	return key

def encrypt(key, text, isfile=False):

	ciphertexts = ''
	print_text = str(text[0:min(50, len(text))]) + '...'
	print "Begin to encrypt:", print_text

	if not isfile:
		for start in xrange(0, len(text), chunk_size(key)):
			end = start + chunk_size(key)
			chunk = text[start:end]
			ciphertext = key.encrypt(chunk, K=0)[0]
			ciphertexts = ciphertexts + base64.b64encode(ciphertext)
			#print len(base64.b64encode(ciphertext)) = 344
			#print len(base64.b64decode(ciphertexts))

	else:
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CFB, iv)
		ciphertexts = iv + cipher.encrypt(text)

	return ciphertexts

def decrypt(key, ciphertexts, isfile=False):

	texts = ''
	if not isfile:
		for start in xrange(0, len(ciphertexts), 344):
			end = start + 344
			ciphertext = ciphertexts[start:end]
			text = key.decrypt(base64.b64decode(ciphertext),)
			texts = texts + text
	else:
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CFB, iv)
		text = cipher.decrypt(ciphertexts)

	return text

def encrypt_filename(key, filename):
	return encrypt(key, filename, isfile=False)

def encrypt_aes(key, aes):
	return encrypt(key, aes, isfile=False)

def decrypt_aes(key, cipheraes):
	return decrypt(key, cipheraes, isfile=False)

def encrypt_file(key, filepath):
	cipherfile = ''
	with open(filepath, 'r') as f:
		content = f.read()
		cipherfile = encrypt(key, content, isfile=True)
	return cipherfile

def decrypt_file(key, filepath):
	text = ''
	with open(filepath, 'r') as f:
		content = f.read()
		cipherfile = decrypt(key, content, isfile=True)
	return cipherfile[16:]

def sign_file(key, cipherfile):
	# calculate hash value
	h = SHA.new()
	h.update(cipherfile)

	signer = PKCS1_PSS.new(key)
	signature = signer.sign(h)
	signtext = base64.b64encode(signature)

	return signtext

def verify_sign(key, signature, cipherfile):
	h = SHA.new()
	h.update(cipherfile)

	signature = base64.b64decode(signature)
	verifier = PKCS1_PSS.new(key)
	result = verifier.verify(h, signature)

	return result


