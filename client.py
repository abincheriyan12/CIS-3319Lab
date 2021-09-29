from des import DesKey
import hmac
import hashlib
import base64
import socket
import sys

# Establishing Connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 3000))
print(s.recv(1024).decode())

# Reading DESkey from DESkey file and defining DESkey
desFile = open("key", "r")
desKeystr = desFile.read()
desFile.close()
key = DesKey(desKeystr.encode('utf-8'))

# Reading HMACkey from file and defining HMACkey
hmacKey = open("hmackey", "r")
hmacKeystr = hmacKey.read()
hmacKey.close()
byteHmacKey = hmacKeystr.encode('utf-8')

while True:
    message = input("Type message: ")
    messageEncoded = message.encode()

    # getting HMAC Digest of message
    HMACdigest = hmac.new(byteHmacKey, messageEncoded, hashlib.sha1).hexdigest()

    # Concantenating original message and HMAC digest
    ConcantMessage = message + " " + HMACdigest

    # Encrypting the Concantenated Message
    ConcantCipherText = key.encrypt(ConcantMessage.encode('utf-8'), padding=True)
    print("--- Sender Side ---")
    print("Shared DES key is: ", desKeystr)
    print("Shared HMAC key is: ", hmacKeystr)
    print("Plain message is: ", message)
    print("Sender side HMAC is: ", HMACdigest)
    print("Sent ciphertext is: ", ConcantCipherText.decode('utf-8', 'ignore'))

    # Sending Concantenated Ciphertext
    print("Sending this as cipher text: ", ConcantCipherText)
    s.send(ConcantCipherText)
    print("<><><><><><><><><><><><><><><><><><<><><<><><><><")

    # Receiving Message
    rcv = s.recv(1024)
    print("--- Receiver Side ---")
    print("Received ciphertext is: ", rcv.decode('utf-8', 'ignore'))

    # Decrypting Concantenated Message
    decrypted = key.decrypt(rcv, padding=True).decode()
    splitCipher = decrypted.split()
    decryptedHMACDigest = splitCipher[-1]
    rm = splitCipher[:-1]
    decryptedMessage = ' '.join([str(elem) for elem in rm])
    print("Received message is: " + decryptedMessage)
    print("Received HMAC is: " + decryptedHMACDigest)

    # Calculating hmac for verification
    HMACcalc = hmac.new(byteHmacKey, decryptedMessage.encode(), hashlib.sha1).hexdigest()
    print("Calculated HMAC is: " + HMACcalc)

    if (HMACcalc == decryptedHMACDigest):
        print("HMAC Verified")
    else:
        print("HMAC NOT VERIFIED")
    print("<><><><><><><><><><><><><><><><><><<><><<><><><><")

    # Exits if "exit" is received
    if decryptedMessage == "exit":
        sys.exit("Exiting...")
s.close()




