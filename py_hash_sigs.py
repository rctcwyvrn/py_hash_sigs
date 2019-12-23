# scripts for generating hash signatures of varying levels of security
# also scripts for attacking them!

from hashlib import md5
import random
import math

def hash_me(xs):
	return [md5(x.encode('ascii')).hexdigest() for x in xs]

def bytes_to_bitstring(m):
	m = ['{0:b}'.format(x) for x in m] #\x01 becomes just 1, but we would want 00000001 in that siutation
	m = ['0'*(8-len(x)) + x for x in m]
	return ''.join(m)

#generate a bitstring of length n
def generate_bitstring(n):
	x = ['1' if random.randint(0,1) == 1 else '0' for _ in range(n)]  #flex dat list concatenation, could make this a oneline if i really really wanted to
	return ''.join(x)

#Generate a key for n bit messages, where each component of the secret key is a 256 bitstring
def generate_long_key(n):
	sk = [generate_bitstring(256) for _ in range(n)]
	return sk

#lamport's one time signature
def lamport_OTS_generate(bitlen):
	sk_0 = generate_long_key(bitlen)
	sk_1 = generate_long_key(bitlen)
	#print(sk_0)

	pk_0 = hash_me(sk_0)
	#print(pk_0)
	pk_1 = hash_me(sk_1)

	return [(sk_0, sk_1), (pk_0, pk_1)]

#Returns a signature made up of a bunch of secret keys
def lamport_OTS_sign(message, sks):
	assert(len(message) == 32)
	bit_msg = bytes_to_bitstring(message)
	assert(len(bit_msg) == 256)

	sig = []
	for i in range(256):
		if bit_msg[i] == '0':
			sig.append(sks[0][i])
		else:
			sig.append(sks[1][i])
	return sig

#You can verify it by hashing the values yourself and seeing if they match what I had hashed when 
#I initially generated the keys (the public keys)

#Brute force forgery would then involve having to find valid pre-images or collisions for the public key hexdigests that matched the bits of 
#the message you wanted to forge
def lamport_OTS_verify(message,sig,pks):
	bit_msg = bytes_to_bitstring(message)
	assert(len(message) == 32)
	assert(len(bit_msg) == 256)

	for i in range(256):
		x = md5(sig[i].encode()).hexdigest()
		if bit_msg[i] == '0':
			if not x == pks[0][i]:
				break
		else:
			if not x == pks[1][i]:
				break
	else:
		return True

	return False

#Motivation for proof structure from https://github.com/Tierion/pymerkletools
class MerkleHashTree:
	leaves = []
	def __init__(self, data):
		print("Generating merkle hash tree. # of leaves = ", len(data))
		for pks in data:
			leaf = md5(''.join(pks[0] + pks[1]).encode('ascii')).hexdigest() #A hash of a public key is all the keys concatenated together, and then hashed
			self.leaves.append(leaf)
		self.generate()
		print(self.leaves)

	def generate(self):
		layer = self.leaves
		for _ in range(int(math.log(len(self.leaves))) + 1):
			pairs = zip(layer[::2], layer[1::2])
			layer = [md5((pair[0] + pair[1]).encode('ascii')).hexdigest() for pair in pairs]

		assert(len(layer) == 1)
		self.root = layer[0]

	def generate_proof(self, index):
		proof = []
		#layer = self.leaves #what the fuck python, this is a reference, not a copy????????/
		layer = self.leaves[:]
		layer[index] = "unknown"

		for _ in range(int(math.log(len(self.leaves))) + 1):
			pairs = zip(layer[::2], layer[1::2])
			layer = []
			for pair in pairs:
				if pair[0] == "unknown":
					proof.append({"pos":"right","val":pair[1]})
					layer.append("unknown")

				elif pair[1] == "unknown": #if the right is unknown, then this value belongs on the left
					proof.append({"pos":"left","val":pair[0]})
					layer.append("unknown")

				else:
					layer.append(md5((pair[0] + pair[1]).encode('ascii')).hexdigest())

		print("proof", proof)
		return proof


#Returns the hash tree
def merkle_hash_tree(pk_list):
	return MerkleHashTree(pk_list)

#Generate the public key tree and secret keys to sign N messages
#The signer would hold onto all of the secret and public keys
#The master public key is used in Merkle proofs that a given hash is within the tree???

merkle_signs_done = 0
merkle_N = 0

def merkle_generate(N):
	global merkle_N, merkle_signs_done
	merkle_N = N
	merkle_signs_done = 0

	pk_list = []
	sk_list = []
	for _ in range(N):
		sks,pks = lamport_OTS_generate(512)
		pk_list.append(pks)
		sk_list.append(sks)

	tree = merkle_hash_tree(pk_list)
	return sk_list, pk_list, tree

def merkle_sign(msg, sk_list, pk_list, tree):
	global merkle_N, merkle_signs_done
	if merkle_signs_done < merkle_N:
		proof = tree.generate_proof(merkle_signs_done)
		res =  [lamport_OTS_sign(msg, sk_list[merkle_signs_done]), pk_list[merkle_signs_done], proof]
		merkle_signs_done+=1
		return res
	else:
		print("Too many signs, make a new key")
		return ['','','']

def merkle_verify_proof(pks, master, proof):
	check = md5(''.join(pks[0] + pks[1]).encode('ascii')).hexdigest()
	for step in proof:
		if step['pos'] == "left": #as mentioned before, pos represents where val goes
			check = md5((step['val'] + check).encode('ascii')).hexdigest()
		else:
			check = md5((check + step['val']).encode('ascii')).hexdigest()
	return check == master


def merkle_verify(msg, sig, pk, master, proof):
	if merkle_verify_proof(pk, master, proof):
		return lamport_OTS_verify(msg, sig, pk)
	else:
		return False


#Optimization #1: Make a smaller signature by only signing the 1 bits
def lamport_optim_sign(message, sk):
	assert(len(message) == 32)
	bit_msg = bytes_to_bitstring(message)
	assert(len(bit_msg) == 256)

	sig = []
	checksum = 0
	for i in range(256):
		if bit_msg[i] == '1':
			sig.append(sk[i])
			checksum+=1
		else:
			sig.append('')

	#max value of checksum is 255, so we potentially need 8 bits -> this is why our secret keys have 8 extra strings
	checksum_bits = "{0:b}".format(checksum)
	checksum_bits = (8-len(checksum_bits))*"0" + checksum_bits
	for i in range(8):
		if checksum_bits[i] == "1":
			sig.append(sk[i])
		else:
			sig.append('')

	return sig

def lamport_optim_verify(message, sig, pk):
	bit_msg = bytes_to_bitstring(message)
	assert(len(message) == 32)
	assert(len(bit_msg) == 256)

	checksum = 0
	for i in range(256):
		x = md5(sig[i].encode()).hexdigest()
		if bit_msg[i] == '1':
			checksum+=1
			if not x == pk[i]:
				break
	else:
		checksum_bits = "{0:b}".format(checksum)
		checksum_bits = (8-len(checksum_bits))*"0" + checksum_bits

		for i in range(8):
			x = md5(sig[256+i].encode()).hexdigest()
			if checksum_bits[i] == "1":
				if not x == pk[i]:
					break
		else:
			return True

		#print("Failed checksum")
		return False

	#print("!!! Signature failed")
	return False

#Generate secret and public keys with the Winternitz time-space tradeoff with bytes
def winternitz_generate(bitlen):
	sk = generate_long_key(int(bitlen/8))
	pk = sk
	for _ in range(256):
		pk = hash_me(pk)
	return sk, pk

#basically just calls hash_me i times
def winternitz_get_sks(i,sk):
	for _ in range(i):
		sk = hash_me(sk)
	return sk

#Signs by using get_sks() to navigate to the right secret key, and append the ith bit/hex string to the signature
def winternitz_sign(message, sk):
	assert(len(message) == 32)
	sig = []
	#Each element of msg is a byte so we can just do this c:
	for i in range(len(message)):
		byte = msg[i]
		key = winternitz_get_sks(byte, sk)
		sig.append(key[i]) #I think??
	return sig

#Verifies the signature by checking if the ith signature really is from the byte-th secret key -> checks this by using get_sks
#Where byte is the ith byte value of the message
def winternitz_verify(msg, sig, pk):
	for i in range(len(msg)):
		byte = msg[i]
		layers = 256 - byte
		check = winternitz_get_sks(layers, sig)
		#We want to check if we hash the ith signature part layers @ of times, we end up at the public key

		return check[i] == pk[i]





if __name__ == "__main__":
	#print(bytes_to_bitstring(b'\xff'))
	msg = b'test'*8
	secret_keys, public_keys = lamport_OTS_generate(512)
	sig = lamport_OTS_sign(msg, secret_keys)
	#print("signature",sig)
	print("Lamport -> Should work:", lamport_OTS_verify(msg, sig, public_keys))
	print("Lamport -> Should fail:",lamport_OTS_verify(b'fail'*8,sig, public_keys))

	print("-"*30)
	num_keys = 8
	sk_list, pk_list, pk_tree = merkle_generate(num_keys)

	for _ in range(num_keys):
		print("*"*30)
		sig, pk_used, proof = merkle_sign(msg, sk_list, pk_list, pk_tree)
		print("Merkle -> Should work:", merkle_verify(msg, sig, pk_used, pk_tree.root, proof))
		print("Merkle -> Should fail:", merkle_verify(b'fail'*8, sig, pk_used, pk_tree.root, proof))
		print("Merkle -> Should fail (failed proof):", merkle_verify(msg, sig, public_keys, pk_tree.root, proof))
	print("*"*30)
	print(merkle_sign(msg, sk_list, pk_list, pk_tree))

	print("-"*30)
	secret_keys, public_keys = lamport_OTS_generate(512 + 8)
	sig = lamport_optim_sign(msg, secret_keys[0])
	#print("signature",sig)
	print("Optimization 1 -> Should work:", lamport_optim_verify(msg, sig, public_keys[0]))
	print("Optimization 1 -> Should fail:",lamport_optim_verify(b'fail'*8,sig, public_keys[0]))

	print("-"*30)
	secret_key, public_key = winternitz_generate(512)
	sig = winternitz_sign(msg, secret_key)
	print("Winternitz -> siglen=", len(sig))
	print("winternitz -> Should work:", winternitz_verify(msg, sig, public_key))
	print("winternitz -> Should fail:",winternitz_verify(b'fail'*8,sig, public_key))