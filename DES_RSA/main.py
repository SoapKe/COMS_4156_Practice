import tkinter
import tkinter.filedialog
import tkinter.messagebox
from time import time

from DES import *
from RSA import *
from Test import *

import sys
import io

# build tk root
root = tkinter.Tk()
# rename the title
root.title("Performance Comparison (DES & RSA) by Ke Xu")

"""

			DES Algorithm

"""

# DES Function
des = DES()

# Enter keys from a file
# Either you can enter the key in the textbox directly
def SetKey_File():
	file = tkinter.filedialog.askopenfile(parent=root, mode='rb', title='Choose a file')
	if file != None:
		key = file.read()
		tk_SetupKey_Textbox_DES.insert(0, key)
		file.close()

# Confirm the key and process the subkeys for DES
def ConfirmKey():
	# root.update()
	key = tk_SetupKey_Textbox_DES.get()
	if key != '':
		des.SetKey(key)
		des.EncryptKey()

		print("DES Key Confirmed")

		# Enable UI
		tk_SetupPlaintext_Button_DES["state"] = 'normal'
		tk_Encrypt_Button_DES["state"] = 'normal'
		tk_SetupCipher_Button_DES["state"] = 'normal'
		tk_Decrypt_Button_DES["state"] = 'normal'
		tk_SetupPlaintext_Textbox_DES["state"] = 'normal'
		tk_SetupCipher_Textbox_DES["state"] = 'normal'
	else:
		# Prompt ---- [key] Input Textbox is blank
		tkinter.messagebox.showinfo('Error', "Enter key for DES Algorithm")

#  Enter plaintext from a file
def DES_SetPlainText_File():
	file = tkinter.filedialog.askopenfile(parent=root, mode='rb', title='Choose a file')
	if file != None:
		txt = file.read()
		tk_SetupPlaintext_Textbox_DES.insert(0, txt)
		file.close()

#  Enter cipher from a file
def DES_SetCipher_File():
	file = tkinter.filedialog.askopenfile(parent=root, mode='rb', title='Choose a file')
	if file != None:
		txt = file.read()
		tk_SetupCipher_Textbox_DES.insert(0, txt)
		file.close()

# Encrpytion: Confirm plaintext and run the DES algorithm
def DES_Encrypt():
	plaintext_input = tk_SetupPlaintext_Textbox_DES.get()
	if plaintext_input != '':
		des.SetInputText(plaintext_input)
		des_cipher = des.Encrypt()
		tkinter.messagebox.showinfo('cipher', des_cipher)

		print('')
		print("Encrption Result:")
		print(des_cipher)


		# Write DES cipher into a file
		fo = open("des_cipher.txt", "w")
		fo.write(str(des_cipher));
		fo.close()

	else:
		# Prompt ---- [plaintext] Input Textbox is blank
		tkinter.messagebox.showinfo('Error', "Enter plaintext for DES Algorithm")		

# Decrpytion: Confirm cipher and run the DES algorithm
def DES_Decrypt():
	cipher_input = tk_SetupCipher_Textbox_DES.get()
	if cipher_input != '':
		des.SetCipherText(cipher_input)
		des_decipher = des.Decrypt()
		tkinter.messagebox.showinfo('plaintxt', des_decipher)

		print('')
		print("Decryption Result:")
		print(des_decipher)


		# Write DES decipher into a file
		fo = open("des_plaintxt.txt", "w")
		fo.write(str(des_decipher));
		fo.close()

	else:
		# Prompt ---- [cipher] Input Textbox is blank
		tkinter.messagebox.showinfo('Error', "Enter cipher for DES Algorithm")		

"""

			RSA Algorithm

"""

# RSA Function
rsa = RSA()

# Generate the Pubilc Key and Private Key from two random large prime number
def RSAKeyGeneration():
	keyLength = tk_SetupKey_Textbox_RSA.get()
	if keyLength != '':
		# Generate Pubilc Key and Private Key
		rsa.KeyGeneration(int(keyLength))

		# Message box
		keys = 'Public: \t' + str(rsa.keyPublic) +'\n\nPrivate:' + str(rsa.keyPrivate)
		tkinter.messagebox.showinfo('Keys', keys)

		# Write RSA Keys into a file
		fo = open("rsa_key.txt", "w")
		fo.write( "Public: " + str(rsa.keyPublic) +" \n" "Private: " + str(rsa.keyPrivate) +" \n");
		fo.close()

		# Shows in CMD
		print('')
		print("RSA Key Generation Completed")
		print(keys)

		# Enable UI
		tk_SetupPlaintext_Button_RSA["state"] = 'normal'
		tk_Encrypt_Button_RSA["state"] = 'normal'
		tk_SetupCipher_Button_RSA["state"] = 'normal'
		tk_Decrypt_Button_RSA["state"] = 'normal'
		tk_SetupPlaintext_Textbox_RSA["state"] = 'normal'
		tk_SetupCipher_Textbox_RSA["state"] = 'normal'
	else:
		# Prompt ---- [key] Input Textbox is blank
		tkinter.messagebox.showinfo('Error', "Enter key length for RSA Algorithm")

#  Enter plaintext from a file
def RSA_SetPlainText_File():
	file = tkinter.filedialog.askopenfile(parent=root, mode='rb', title='Choose a file')
	if file != None:
		txt = file.read()
		tk_SetupPlaintext_Textbox_RSA.insert(0, txt)
		file.close()

#  Enter cipher from a file
def RSA_SetCipher_File():
	file = tkinter.filedialog.askopenfile(parent=root, mode='rb', title='Choose a file')
	if file != None:
		txt = file.read()
		tk_SetupCipher_Textbox_RSA.insert(0, txt)
		file.close()

# Encrpytion: Confirm plaintext and run the RAS algorithm
def RSA_Encrypt():
	# RSA Encryption
	RSA_cipher = rsa.Encryption(tk_SetupPlaintext_Textbox_RSA.get(), rsa.keyPublic, rsa.n)

	# Message Box
	tkinter.messagebox.showinfo('Cipher', RSA_cipher)


	# Write RSA cipher into a file
	fo = open("rsa_cipher.txt", "w")
	fo.write(str(RSA_cipher));
	fo.close()

	# Shows in CMD
	print("\nCipher: ")
	print(RSA_cipher)

# Decrpytion: Confirm cipher and run the RAS algorithm
def RSA_Decrypt():
	# RSA Decryption
	RSA_plaintxt = rsa.Decryption(tk_SetupCipher_Textbox_RSA.get(), rsa.keyPrivate, rsa.n)

	# Message Box	
	tkinter.messagebox.showinfo('plaintxt', RSA_plaintxt)


	# Write RSA original plaintxt into a file
	fo = open("rsa_plaintxt.txt", "w")
	fo.write(RSA_plaintxt);
	fo.close()

	# Shows in CMD
	print("\nPlaintxt: ")
	print(RSA_plaintxt)

"""

			DES & RSA Algorithm
			Time Comparison

"""

def ComparisonTest():
	plaintext_input = tk_SetupPlaintext_Textbox_Test.get()

	runtime = ''

	if plaintext_input != '':
		start = time()

		# DES Ket
		# ConfirmKey()
		des_key = tk_SetupKey_Textbox_DES.get()
		if des_key != '':
			des.SetKey(des_key)
			des.EncryptKey()

		# DES Encryption
		des.SetInputText(plaintext_input)
		des_cipher = des.Encrypt()

		# DES Decryption
		des.SetCipherText(des_cipher)
		des_decipher = des.Decrypt()

		stop = time()

		runtime += ('DES runtime:' + str(stop-start) + "s\n")

		start = time()

		# RSA Key
		rsa_keyLength = tk_SetupKey_Textbox_RSA.get()
		if rsa_keyLength != '':
			# Generate Pubilc Key and Private Key
			rsa.KeyGeneration(int(rsa_keyLength))

		# RSA Encryption
		rsa_cipher = rsa.Encryption(plaintext_input, rsa.keyPublic, rsa.n)

		# RSA Decryption
		rsa_plaintxt = rsa.Decryption(rsa_cipher, rsa.keyPrivate, rsa.n)
		
		stop = time()

		runtime += ('RSA runtime:' + str(stop-start) + "s\n\n")

		tkinter.messagebox.showinfo('runtime', runtime)

		# Write Comprison Report into a file
		fo = open("des_rsa_timetest.txt", "a")
		fo.write("\t\t\t\tComparison Result\n")
		fo.write("Input plaintxt: " + plaintext_input)
		fo.write("\n")
		fo.write("DES Key: " + des_key)
		fo.write("\n\n")
		fo.write("DES Cipher: " + des_cipher)
		fo.write("\n")
		fo.write("DES decipher: " + des_decipher)
		fo.write("\n\n\n")

		rsa_keys = 'Public: \t' + str(rsa.keyPublic) +'\n\nPrivate:' + str(rsa.keyPrivate)
		fo.write("RSA Key: \n" + rsa_keys)
		fo.write("\n\n")
		fo.write("RSA Cipher: " + str(rsa_cipher))
		fo.write("\n")
		fo.write("RSA decipher: " + str(rsa_plaintxt))
		fo.write("\n\n")

		fo.write(runtime)
		fo.write("\n\n")
		fo.close()
	else:
		# Prompt ---- [key] Input Textbox is blank
		tkinter.messagebox.showinfo('Error', "Enter plaintxt for Comparison Test")

# UI configuration 
root.configure(background = 'LightCyan')

# UI : Setup Labels
tk_Title_Label_DES = tkinter.Label(root, text = "DES Demo:", width = 10, height = 2, bg = 'LightCyan', font = 'Helvetica 14 bold italic')
tk_Title_Label_DES.grid(row = 0)

tk_TitleKey_Label_DES = tkinter.Label(root, text = "Key:", width = 6, height=3,  bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitleKey_Label_DES.grid(row = 1)

tk_TitlePlaintext_Label_DES = tkinter.Label(root, text = "Plaintxt:", width = 6, height=3, 	bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitlePlaintext_Label_DES.grid(row = 2)

tk_TitleCipher_Label_DES = tkinter.Label(root, text = "Cipher:", width = 6,	height=3,  bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitleCipher_Label_DES.grid(row = 3)

# UI : Setup Textbox
tk_SetupKey_Textbox_DES = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan')
tk_SetupKey_Textbox_DES.grid(row = 1, column = 1)

tk_SetupPlaintext_Textbox_DES = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupPlaintext_Textbox_DES.grid(row = 2, column = 1)

tk_SetupCipher_Textbox_DES = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupCipher_Textbox_DES.grid(row = 3, column = 1)


# UI : Setup Button
tk_SetupKey_Button_DES = tkinter.Button(root, text="File", width = 6, command = SetKey_File, highlightbackground = 'LightCyan')
tk_SetupKey_Button_DES.grid(row = 1, column = 2)

tk_ConfirmKey_Button_DES = tkinter.Button(root, text="Confirm", width = 6, command = ConfirmKey, highlightbackground = 'LightCyan')
tk_ConfirmKey_Button_DES.grid(row = 1, column = 3)

tk_SetupPlaintext_Button_DES = tkinter.Button(root, text="File", width = 6, command = DES_SetPlainText_File, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupPlaintext_Button_DES.grid(row = 2, column = 2)

tk_Encrypt_Button_DES = tkinter.Button(root, text="Encrypt", width = 6, command = DES_Encrypt, highlightbackground = 'LightCyan', state = 'disabled')
tk_Encrypt_Button_DES.grid(row = 2, column = 3)

tk_SetupCipher_Button_DES = tkinter.Button(root, text="File", width = 6, command = DES_SetCipher_File, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupCipher_Button_DES.grid(row = 3, column = 2)

tk_Decrypt_Button_DES = tkinter.Button(root, text="Decrypt", width = 6, command = DES_Decrypt, highlightbackground = 'LightCyan', state = 'disabled')
tk_Decrypt_Button_DES.grid(row = 3, column = 3)


"""

			RSA Algorithm
			UI Configuration

"""
# UI : Setup Labels
tk_Title_Label_RSA = tkinter.Label(root, text = "RSA Demo:", width = 10, height = 2, bg = 'LightCyan', font = 'Helvetica 14 bold italic')
tk_Title_Label_RSA.grid(row = 4)

tk_TitleKey_Label_RSA = tkinter.Label(root, text = "Key:", width = 15, height=3,  bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitleKey_Label_RSA.grid(row = 5)

tk_TitlePlaintext_Label_RSA = tkinter.Label(root, text = "Plaintxt:", width = 6, height=3, 	bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitlePlaintext_Label_RSA.grid(row = 6)

tk_TitleCipher_Label_RSA = tkinter.Label(root, text = "Cipher:", width = 6,	height=3,  bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitleCipher_Label_RSA.grid(row = 7)

# UI : Setup Textbox
tk_SetupKey_Textbox_RSA = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan')
tk_SetupKey_Textbox_RSA.grid(row = 5, column = 1)

tk_SetupPlaintext_Textbox_RSA = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupPlaintext_Textbox_RSA.grid(row = 6, column = 1)

tk_SetupCipher_Textbox_RSA = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupCipher_Textbox_RSA.grid(row = 7, column = 1)

# UI : Setup Button
tk_GenerateKey_Button_RSA = tkinter.Button(root, text="Generate", width = 8, command = RSAKeyGeneration, highlightbackground = 'LightCyan')
tk_GenerateKey_Button_RSA.grid(row = 5, column = 2)

tk_SetupPlaintext_Button_RSA = tkinter.Button(root, text="File", width = 6, command = RSA_SetPlainText_File, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupPlaintext_Button_RSA.grid(row = 6, column = 2)

tk_Encrypt_Button_RSA = tkinter.Button(root, text="Encrypt", width = 6, command = RSA_Encrypt, highlightbackground = 'LightCyan', state = 'disabled')
tk_Encrypt_Button_RSA.grid(row = 6, column = 3)

tk_SetupCipher_Button_RSA = tkinter.Button(root, text="File", width = 6, command = RSA_SetCipher_File, highlightbackground = 'LightCyan', state = 'disabled')
tk_SetupCipher_Button_RSA.grid(row = 7, column = 2)

tk_Decrypt_Button_RSA = tkinter.Button(root, text="Decrypt", width = 6, command = RSA_Decrypt, highlightbackground = 'LightCyan', state = 'disabled')
tk_Decrypt_Button_RSA.grid(row = 7, column = 3)


"""

			Comparison Test
			UI Configuration

"""
# UI : Setup Labels
tk_Title_Label_Test = tkinter.Label(root, text = "Comparison\nTest:", width = 10, height = 2, bg = 'LightCyan', font = 'Helvetica 14 bold italic')
tk_Title_Label_Test.grid(row = 8)

tk_TitlePlaintext_Label_Test = tkinter.Label(root, text = "Plaintxt:", width = 6, height=3, 	bg = 'LightCyan', font = 'Helvetica 12 bold')
tk_TitlePlaintext_Label_Test.grid(row = 9)

# UI : Setup Textbox
tk_SetupPlaintext_Textbox_Test = tkinter.Entry(root, text = "", width = 80, highlightbackground = 'LightCyan')
tk_SetupPlaintext_Textbox_Test.grid(row = 9, column = 1)

# UI : Setup Button
tk_SetupPlaintext_Button_Test = tkinter.Button(root, text="Run", width = 8, command = ComparisonTest, highlightbackground = 'LightCyan')
tk_SetupPlaintext_Button_Test.grid(row = 9, column = 2)

# UI: Set windows size and initial position
root.geometry('850x600+100+100')  

# UI: Setup root
root.mainloop()