import random


class RSA(object):

	n = 0;
	keyPublic = 0
	keyPrivate = 0

	"""docstring for RSA"""
	def __init__(self):
		pass

	def FastExpMod(self, b, e, m):
		"""
		e = e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n)

		b^e = b^(e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n))
			= b^(e0*(2^0)) * b^(e1*(2^1)) * b^(e2*(2^2)) * ... * b^(en*(2^n)) 

		b^e mod m = ((b^(e0*(2^0)) mod m) * (b^(e1*(2^1)) mod m) * (b^(e2*(2^2)) mod m) * ... * (b^(en*(2^n)) mod m) mod m
		"""
		result = 1
		# e = int(e)
		while e != 0:
			if (e&1) == 1:
				# ei = 1, then mul
				result = (result * b) % m
			e >>= 1
			# b, b^2, b^4, b^8, ... , b^(2^n)
			b = (b*b) % m
		return result

	def IsPrimeNumber(self, n):
		q = n - 1
		k = 0
		#Find k, q, satisfied 2^k * q = n - 1
		while q % 2 == 0:
			k += 1;
			q /= 2;

		a = random.randint(2, n-2);
		#If a^q mod n= 1, n maybe is a prime number
		if self.FastExpMod(a, int(q), n) == 1:
			return True
		#If there exists j satisfy a ^ ((2 ^ j) * q) mod n == n-1, n maybe is a prime number
		for j in range(0, k):
			if self.FastExpMod(a, int((2**j)*q), n) == n - 1:
				return True
		#a is not a prime number
		return False

	def FindPrime(self, halfkeyLength):
		while True:
			#Select a random number n 
			n = random.randint(0, 1 << halfkeyLength)
			if n % 2 != 0:
				found = True
				#If n satisfy primeTest 10 times, then n should be a prime number
				for i in range(0, 10):
					if not self.IsPrimeNumber(n):
						found = False
						break
				if found:
					return n

	def ExtendedGCD(self, a, b):
		#a*xi + b*yi = ri
		if b == 0:
			return (1, 0, a)
		#a*x1 + b*y1 = a
		x1 = 1
		y1 = 0
		#a*x2 + b*y2 = b
		x2 = 0
		y2 = 1
		while b != 0:
			q = a // b
			#ri = r(i-2) % r(i-1)
			r = a % b
			a = b
			b = r
			#xi = x(i-2) - q*x(i-1)
			x = x1 - q*x2
			x1 = x2
			x2 = x
			#yi = y(i-2) - q*y(i-1)
			y = y1 - q*y2
			y1 = y2
			y2 = y
		return(x1, y1, a)

	def GeneratePublicKey(self, fn, halfkeyLength):
		while True:
			#e and fn are relatively prime
			e = random.randint(0, 1 << halfkeyLength)
			(x, y, r) = self.ExtendedGCD(e, fn)
			if r == 1:
				return e

	def GeneratePrivateKey(self, fn, keyPublic):
		(x, y, r) = self.ExtendedGCD(fn, self.keyPublic)
		#y maybe < 0, so convert it 
		if y < 0:
			return fn + y
		return y

	def KeyGeneration(self, keyLength):
		#generate public key and private key
		p = self.FindPrime(int(keyLength//2))
		q = self.FindPrime(int(keyLength//2))
		self.n = p * q
		fn = (p-1) * (q-1)

		self.keyPublic = self.GeneratePublicKey(fn, int(keyLength / 2))
		self.keyPrivate = self.GeneratePrivateKey(fn, int(self.keyPublic))
		self.keyPrivate = int(self.keyPrivate)

		# Shows in CMD
		keys = 'Public: \t' + str(self.keyPublic) +'\n\nPrivate:' + str(self.keyPrivate)
		print("RSA Key Generation Completed")
		print(keys)

	def Encryption(self, M, keyPublic, n):
		#Ciper text = M^e mod n
		M_int10 = int(self.StringToBin(M), 2)
		# print("M_int10 = " + str(M_int10))

		return self.FastExpMod(M_int10, self.keyPublic, n)

	def Decryption(self, C, keyPrivate, n):
		#Message = C^d mod n

		# Get M_int10
		M_int10 = self.FastExpMod(int(C), self.keyPrivate, n)
		# print(M_int10)
		# print("")

		# M_int10 => M_int2
		M_int2 = bin(M_int10).replace('0b', '')

		# print(len_M_int2)
		len_M_int2 = M_int2.count("1") + M_int2.count("0")
		if (len_M_int2 % 8 != 0):
			M_int2 = M_int2.zfill( len_M_int2 + (8 - (len_M_int2 % 8)) )

		# print(len_M_int2)

		# print(M_int2)
		# print("")

		# M_int2 to String
		return self.BinToString(str(M_int2))

	# Convert string to binary code
	def StringToBin(self, string):
		# ord() return the ascii value of a char
		# replace 0b with ''
		# ASCII code in decimal range from 0 - 127
		# ASCII code in binary range from 0000 0000 - 01111111
		# str.zfill(width) to fill the str in a fix length [width] with zero on the left
		# e.g. 1001100 -> 01001100
		result = ''
		for c in string:
			binary_char = str(bin(ord(c)).replace('0b', ''))
			binary_char_added_zero = binary_char.zfill(8)
			result += ''.join(binary_char_added_zero)

		return result

	# Convert bin code to string with characters coded by ascii
	def BinToString(self, string):
		words = ''
		number = len(string)/8
		for i in range(int(number)):
			# Change the ascii code into decimal (from binary)
			word_ascii_code_dec = int(string[i*8 : i*8 + 8], 2)

			# ASCII code == 0 when Value == NUL(null)
			# chr(int) return a char para according to the ascii code to that [int] 
			if word_ascii_code_dec != 0:
				word_ascii_code = chr(word_ascii_code_dec)
				words += ''.join(word_ascii_code)
			else:
				pass

		return words

# start = time()
# #Unit Testing
# rsa = RSA()
# rsa.KeyGeneration(256)

# # #AES keyLength = 256
# X = random.randint(0, 1<<4)

# C = rsa.Encryption(X, rsa.keyPublic, rsa.n)
# M = rsa.Decryption(C, rsa.keyPrivate, rsa.n)
# print "PlainText:", X
# print "Encryption of plainText:", C
# print "Decryption of cipherText:", M

# stop = time()
# print(str(stop-start) + "s")
