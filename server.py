import socket
import struct
from cryptography.fernet import Fernet

ICMP_DATA_FMT = "s"
KEY = b'QQ1m1OL9u22qNWNfUtj8fQwXuPLIfF7aBoQPi-x5d9M='

def decrypt(ciphertext):
    f = Fernet(KEY)
    plaintext = f.decrypt(ciphertext)
    return plaintext

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #create a raw socket

    while 1:
        packet, source = s.recvfrom(1024) #receive the packet

        data = packet[28:] #get the data

        ciphertext = struct.pack(f'{len(packet[28:])}' + ICMP_DATA_FMT, data)

        plaintext = decrypt(ciphertext)

        print("######### PACKET RECEIVED #########")
        print("Source      : ", source)
        print("Message     : ", plaintext.decode())
        print("Packet received successfully!")
        print("###################################")

def main():
    server()

main()
