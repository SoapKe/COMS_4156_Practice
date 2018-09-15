from DES import *
from RSA import *
from time import time

class Test(object):
	"""docstring for Test"""
	def __init__(self, testData):
		self.testData = testData
		self.desRuntime = []
		self.rsaRuntime = []
		self.runtime = ''

	def RuntimeTest(self):
		data = self.testData.strip().split('\n')
		for i in range(len(data)):

			start = time()

			des = DES()
			key = '0001001100110100010101110111100110011011101111001101111111110001'
			des.SetKey(key)
			des.EncryptKey()
			des.SetInputText(data[i])
			des.SetCipherText(des.Encrypt())
			desResult = des.Decrypt()
			
			stop = time()
			self.runtime += ('DES runtime:' + str(stop-start) + "s\n")

			start = time()

			rsa = RSA()
			rsa.KeyGeneration(128)
			rsaResult = rsa.Decryption(rsa.Encryption(int(data[i]), rsa.keyPublic, rsa.n), rsa.keyPrivate, rsa.n)

			stop = time()
			self.runtime += ('RSA runtime:' + str(stop-start) + "s\n\n")

		return self.runtime