class DES(object):
	"""docstring for DES"""
	PC1_Array = [ 	
					57,	49,	41,	33,	25,	17,	9,
					1 ,	58,	50,	42,	34,	26,	18,
					10, 2,	59,	51,	43,	35,	27,
					19,	11, 3,	60,	52,	44,	36,
					63,	55,	47,	39,	31,	23,	15,
					7 ,	62,	54,	46,	38,	30,	22,
					14, 6,	61,	53,	45,	37,	29,
					21,	13, 5,	28,	20,	12, 4 
				]

	PC2_Array = [ 	
					14,	17,	11,	24, 1, 	5, 	3,	28,
					15, 6,	21,	10,	23,	19,	12, 4,
					26, 8,	16, 7,	27,	20,	13, 2,
					41,	52,	31,	37,	47,	55,	30,	40,
					51,	45,	33,	48,	44,	49,	39,	56,
					34,	53,	46,	42,	50,	36,	29,	32 
				]
 
	Left_Shift_Nums = [	1,
						1,
						2,
						2,
						2,
						2,
						2,
						2,
						1,
						2,
						2,
						2,
						2,
						2,
						2,
						1
					]

	IP_Array = [ 	
					58,	50,	42,	34,	26,	18,	10,	2,
					60,	52,	44,	36,	28,	20,	12,	4,
					62,	54,	46,	38,	30,	22,	14,	6,
					64,	56,	48,	40,	32,	24,	16,	8,
					57,	49,	41,	33,	25,	17, 9,	1,
					59,	51,	43,	35,	27,	19,	11,	3,
					61,	53,	45,	37,	29,	21,	13,	5,
					63,	55,	47,	39,	31,	23,	15,	7
				]

	E_SELECTION_Array = [ 
							32, 1, 	2, 	3, 	4, 	5,
							4, 	5, 	6, 	7, 	8, 	9,
							8, 	9,	10,	11,	12,	13,
							12,	13,	14,	15,	16,	17,
							16,	17,	18,	19,	20,	21,
							20,	21,	22,	23,	24,	25,
							24,	25,	26,	27,	28,	29,
							28,	29,	30,	31,	32, 1
						]

	S_BOX_Array = 	[

					# S BOX 1
						[	
							14,	4,	13,	1,	2,	15,	11,	8,	3,	10,	6,	12,	5,	9,	0,	7,
							0,	15,	7,	4,	14,	2,	13,	1,	10,	6,	12,	11,	9,	5,	3,	8,
							4,	1,	14,	8,	13,	6,	2,	11,	15,	12,	9,	7,	3,	10,	5,	0,
							15,	12,	8,	2,	4,	9,	1,	7,	5,	11,	3,	14,	10,	0,	6,	13 
						],

					# S BOX 2
						[ 
							15,	1,	8,	14,	6,	11,	3,	4,	9,	7,	2,	13,	12,	0,	5,	10,
							3,	13,	4,	7,	15,	2,	8,	14,	12,	0,	1,	10,	6,	9,	11,	5,
							0,	14,	7,	11,	10,	4,	13,	1,	5,	8,	12,	6,	9,	3,	2,	15,
							13,	8,	10,	1,	3,	15,	4,	2,	11,	6,	7,	12,	0,	5,	14,	90 
						],

					# S BOX 3
						[ 
							10,	0,	9,	14,	6,	3,	15,	5,	1,	13,	12,	7,	11,	4,	2,	8,
							13,	7,	0,	9,	3,	4,	6,	10,	2,	8,	5,	14,	12,	11,	15,	1,
							13,	6,	4,	9,	8,	15,	3,	0,	11,	1,	2,	12,	5,	10,	14,	7,
							1,	10,	13,	0,	6,	9,	8,	7,	4,	15,	14,	3,	11,	5,	2,	12 
						],

					# S BOX 4
						[ 
							7,	13,	14,	3,	0,	6,	9,	10,	1,	2,	8,	5,	11,	12,	4,	15,
							13,	8,	11,	5,	6,	15,	0,	3,	4,	7,	2,	12,	1,	10,	14,	9,
							10,	6,	9,	0,	12,	11,	7,	13,	15,	1,	3,	14,	5,	2,	8,	4,
							3,	15,	0,	6,	10,	1,	13,	8,	9,	4,	5,	11,	12,	7,	2,	14 
						],

					# S BOX 5
						[ 
							2,	12,	4,	1,	7,	10,	11,	6,	8,	5,	3,	15,	13,	0,	14,	9,
							14,	11,	2,	12,	4,	7,	13,	1,	5,	0,	15,	10,	3,	9,	8,	6,
							4,	2,	1,	11,	10,	13,	7,	8,15,	9,	12,	5,	6,	3,	0,	14,
							11,	8,	12,	7,	1,	14,	2,	13,	6,	15,	0,	9,	10,	4,	5,	3 
						],

					# S BOX 6
						[ 
							12,	1,	10,	15,	9,	2,	6,	8,	0,	13,	3,	4,	14,	7,	5,	11,
							10,	15,	4,	2,	7,	12,	9,	5,	6,	1,	13,	14,	0,	11,	3,	8,
							9,	14,	15,	5,	2,	8,	12,	3,	7,	0,	4,	10,	1,	13,	11,	6,
							4,	3,	2,	12,	9,	5,	15,	10,	11,	14,	1,	7,	6,	0,	8,	13 
						],

					# S BOX 7
						[ 
							4,	11,	2,	14,	15,	0,	8,	13,	3,	12,	9,	7,	5,	10,	6,	1,
							13,	0,	11,	7,	4,	9,	1,	10,	14,	3,	5,	12,	2,	15,	8,	6,
							1,	4,	11,	13,	12,	3,	7,	14,	10,	15,	6,	8,	0,	5,	9,	2,
							6,	11,	13,	8,	1,	4,	10,	7,	9,	5,	0,	15,	14,	2,	3,	12 
						],

					# S BOX 8
						[ 
							13,	2,	8,	4,	6,	15,	11,	1,	10,	9,	3,	14,	5,	0,	12,	7,
							1,	15,	13,	8,	10,	3,	7,	4,	12,	5,	6,	11,	0,	14,	9,	2,
							7,	11,	4,	1,	9,	12,	14,	2,	0,	6,	10,	13,	15,	3,	5,	8,
							2,	1,	14,	7,	4,	10,	8,	13,	15,	12,	9,	0,	3,	5,	6,	11 
						]
					]

	P_Array = 	[	
					16,	7,	20,	21,
					29,	12,	28,	17,
					1 ,	15,	23,	26, 
					5,	18,	31,	10,
					2 ,	8,	24,	14,
					32,	27, 3, 	9,
					19,	13,	30, 6,
					22,	11, 4,	25 
				]

	IP_Inverse_Array = [ 
							40,	8,	48,	16,	56,	24,	64,	32,
							39,	7,	47,	15,	55,	23,	63,	31,
							38,	6,	46,	14,	54,	22,	62,	30,
							37,	5,	45,	13,	53,	21,	61,	29,
							36,	4,	44,	12,	52,	20,	60,	28,
							35,	3,	43,	11,	51,	19,	59,	27,
							34,	2,	42,	10,	50,	18,	58,	26,
							33,	1,	41, 9,	49,	17,	57,	25 
						]
		

	def __init__(self):
		self.C0 = ''
		self.D0 = ''
		self.L0 = ''
		self.R0 = ''
		self.key = ''
		self.sub_keys = []
		self.input_text = ''
		self.cipher_text = ''
		self.S_Box_Result = ''
		self.remainder = 0
		self.blockNum = 0

	def SetKey(self, key):
		self.sub_keys = []
		# The type of INPUT [key] from file is "bytes"
		if isinstance(key, bytes):
			self.key = bytes.decode(key)
		# The typr of INPUT [key] from txt textbox is "str"
		else:
			self.key = key

		# print("DES Key Confirmed")

	def SetInputText(self, input_text):
		self.input_text = input_text

	def SetCipherText(self, cipher_text):
		self.cipher_text = cipher_text

	def EncryptKey(self):
		self.PC1()
		self.KeyPermutation()

	# Select 56 charactors from the 64-bits key
	def PC1(self):
		# Initialize para
		self.C0 = ''
		self.D0 = ''

		# Setup C0 & D0
		for i in range(0, 28):
			self.C0 += self.key[self.PC1_Array[i] - 1]
		for i in range(28, 56):
			self.D0 += self.key[self.PC1_Array[i] - 1]

	# Left shift opearation sub_keys to get 16 new sub_keys
	def KeyPermutation(self):
		for i in range(16):
			self.C0 = self.LeftShift( self.C0, self.Left_Shift_Nums[i] )
			self.D0 = self.LeftShift( self.D0, self.Left_Shift_Nums[i] )
			Cn_Dn = self.C0 + self.D0
			subkey = ''
			for order in self.PC2_Array:
				subkey += Cn_Dn[order - 1]
			self.sub_keys.append(subkey)

	# Left Shift Opearation on String para
	def LeftShift(self, string, shift_num):
		# Lest Shift characters of the number of shift_num
		return string[shift_num:] + string[:shift_num]

	def Encrypt(self):
		# Initialize para
		cipher_result = ''

		# Convert input_text into binary code
		self.input_text = self.StringToBin(self.input_text)

		# Ensuring input text could be divide into int number of blocks
		self.remainder = len(self.input_text) % 64

		if(self.remainder != 0):
			for i in range(64 - self.remainder):
				self.input_text += '0'

		# Encrypting each blocks
		self.blockNum = len(self.input_text)/64
		input_text_stored = self.input_text

		for i in range(int(self.blockNum)):
			self.input_text = input_text_stored[i*64 : i*64 + 64]
			cipher_result += self.EncryptBlock64()

		# Return Cipher in Hex
		# print('')
		# print("Encrption Result:")
		# print(self.BinToHex(cipher_result))
		return self.BinToHex(cipher_result)

	def EncryptBlock64(self):
		# Initialize para
		self.cipher_text = ''

		# Initial Permutation
		input_text_IP = ''
		for order in self.IP_Array:
			input_text_IP += self.input_text[order - 1]

		# Division L0 & R0
		self.L0 = input_text_IP[:32]
		self.R0 = input_text_IP[-32:]
		
		# Encrption Realization 
		for i in range(16):
			last_L0 = self.L0
			self.L0 = self.R0
			self.R0 = str( bin(int(last_L0, 2) ^ int(self.F(i), 2) ).replace('0b', '').zfill(32))

		# Combine Iteration Result
		L16R16 = self.R0 + self.L0

		# Initial Permutation Inverse
		for order in self.IP_Inverse_Array:
			self.cipher_text += L16R16[order - 1]

		return self.cipher_text

	def F(self, i):
		# Initialize para
		self.S_Box_Result = ''

		# Rearrange the R0 with E_SELECTION_Array
		eR0 = ''
		for order in self.E_SELECTION_Array:
			eR0 += self.R0[order - 1]

		# XOR Result
		subkey_XOR_eR0 = str(bin(int(eR0, 2) ^ int(self.sub_keys[i], 2)).replace('0b', '').zfill(48))
		
		# S Box Operation
		for i in range(8):

			s_row = int( ( subkey_XOR_eR0[i * 6] + subkey_XOR_eR0[i * 6 + 5]), 2)

			s_column = int( ( subkey_XOR_eR0[(i * 6 + 1 ): (i * 6 + 5)]), 2 )

			self.S_Box_Result += str(bin(self.S_BOX_Array[i][ s_row * 16 + s_column ]).replace('0b','').zfill(4))

		# P Operation on S_Box_Result
		S_Box_Result_P = ''
		for order in self.P_Array:
			S_Box_Result_P += self.S_Box_Result[order - 1]

		return S_Box_Result_P

	def Decrypt(self):
		# Initialize para
		plain_text_result_bin = ''

		# Convert Hex to Bin
		self.cipher_text = self.HexToBin(self.cipher_text)

		# Decrypting each blocks
		cipherBackup = self.cipher_text		
		self.blockNum = len(self.cipher_text)/64

		for i in range(int(self.blockNum)):
			self.cipher_text = cipherBackup[i*64 : i*64 + 64]
			plain_text_result_bin += self.DecryptCipher()
		
		# Return original string
		# print('')
		# print("Decryption Result:")
		# print(self.BinToHex(plain_text_result_bin))
		return self.BinToString(plain_text_result_bin)

	# Return a binary value of the block
	def DecryptCipher(self):
		# Inversion of cipher_text
		cipherInvInt = [0 for i in range(64)]
		for i in range(64):
			cipherInvInt[self.IP_Inverse_Array[i] - 1] = self.cipher_text[i]
		cipherInverse = ''.join(cipherInvInt)
		self.R0 = cipherInverse[ : 32]
		self.L0 = cipherInverse[-32 : ]

		# Decrpyt the cipher_text by reversing the sequence of sub_keys and switching the left and right part
		for i in range(16):
			last_R0 = self.R0
			self.R0 = self.L0
			self.L0 = str(bin(int(last_R0, 2)^int(self.F(15 - i),2)).replace('0b', '').zfill(32))

		# Get binary code without IP Inversion
		origin_bin_IP = self.L0 + self.R0

		# Get original binary code
		origin_bin = [0 for i in range(64)]
		for i in range(64):
			origin_bin[self.IP_Array[i]-1] = origin_bin_IP[i]

		# .join() help to join a list into a string
		# e.g. '-'.join([0, 0, 1, 1]) = "0-0-1-1"
		return ''.join(origin_bin)

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

    # Convert hexadecimal code to binary code
	def HexToBin(self, string):
		result = ''
		for c in string:
			# Hex to Bin, store in a string
			# Without ahead 0
			# e.g. 0110 1000 stored as 110 1000
			hex_char = str(bin(int(c, 16)).replace('0b',''))

			# Fill the front 0
			# str.rjust(4, '0') == str.zfill(4)
			hex_char_added_zero = hex_char.zfill(4)

			# Store the result
			result += ''.join(hex_char_added_zero)

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

	# Convert bin code to hex code
	def BinToHex(self, string):
		result = ''
		number = len(string)/4
		for i in range(int(number)):
			# Bin to Hex, store in a string
			bin_code = int(string[i * 4 : i * 4 + 4], 2)
			hex_char = hex(bin_code).replace('0x','')
			result += ''.join(hex_char)
		
		return result