from Crypto.Cipher import AES


MESSAGE = "Hello World"
KEY = b'1234567890123456'

def main():
    cipher = AES.new(KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(MESSAGE.encode('utf-8'))

    print("The message is encrypted to: ", ciphertext)
    print("The tag is: ", tag)
    print("The nonce is: ", nonce)


    # get nonce, tag and ciphertext
    #nonce, tag, ciphertext = 
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

main()