from secrets import randbelow
import socket
import sys
import struct
from cryptography.fernet import Fernet

MESSAGE = "Hello World"
KEY = b'QQ1m1OL9u22qNWNfUtj8fQwXuPLIfF7aBoQPi-x5d9M=' # Generated using Fernet.generate_key()
TARGET_IP = "127.0.0.1"
TARGET_PORT = 1

ICMP_HEADER_FMT = "bbHHh"
ICMP_DATA_FMT = "s"
ICMP_TYPE = 47
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = randbelow(65535) # generate a random ID
ICMP_SEQUENCE = 1

# Handles User IP Input
def input_address():
    ip = input("Enter destination IP: ") #get the IP from the user
    port = TARGET_PORT
    dest = (ip, port) # create a tuple of the ip and port

    try: # check if message is valid ip address
        socket.inet_aton(ip)
        return dest
    except socket.error: # otherwise print error and exit
        print("Invalid IP address")
        sys.exit()

# Handles User Message Input
def input_msg():
    msg = input("Enter message!: ") #get the message from the user
    return msg

# Calculate the checksum of our ICMP packet
# Borrowed from https://github.com/avaiyang/ICMP-Pinger/blob/master/ICMP_Pinger.py
def checksum(icmp_packet): 
    icmp_packet_bytes = bytearray(icmp_packet) # convert the packet to bytes
    csum = 0 # zeroing checksum
    countTo = (len(icmp_packet_bytes) // 2) * 2  # countTo is the length of the packet in bytes, ignoring any trailing odd byte that may be present. This is //2 because each 16-bit word of the ICMP header contains 2 bytes.

    # Loop through the packet, counting 16-bit words
    for count in range(0, countTo, 2):
        thisVal = icmp_packet_bytes[count+1] * 256 + icmp_packet_bytes[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    # Handle the case where the packet's length is odd
    if countTo < len(icmp_packet_bytes):
        csum = csum + icmp_packet_bytes[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff) # Add the 1's complement of the sum to the 16-bit result
    csum = csum + (csum >> 16) # Add carry
    answer = ~csum # Invert and truncate to 16 bits
    answer = answer & 0xffff # Swap bytes
    answer = answer >> 8 | (answer << 8 & 0xff00) # Convert to network byte order
    return answer

def encrypt(msg):
    f = Fernet(KEY)
    ciphertext = f.encrypt(msg.encode())
    return ciphertext

def client(dest, msg):
    # Enrypt the message
    ciphertext = encrypt(msg)

    # Make Dummy header and data to calculate checksum
    header = struct.pack(ICMP_HEADER_FMT, ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQUENCE) # Make a dummy header
    data = struct.pack(f'{len(ciphertext)}' + ICMP_DATA_FMT, ciphertext) # Make data struct of message
    csum = checksum(header + data) # Calculate the checksum on the data and the dummy header.

    # Get the right checksum
    csum = socket.htons(csum) #Convert 16-bit integers from host to network byte order

    # Make the header and data again and put in the right checksum
    header = struct.pack(ICMP_HEADER_FMT, ICMP_TYPE, ICMP_CODE, csum, ICMP_ID, ICMP_SEQUENCE)
    packet = header + data # Make the ICMP Packet

    # Send the ICMP Packet to the destination
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #create a raw socket
    s.sendto(packet, dest) #send the message to the destination
    print("Packet sent successfully!")

def main():
    print("")
    print("####### SENDING PACKET #######")
    dest = input_address()
    msg = input_msg()
    print("Destination : ", dest)
    print("Message     : ", msg)
    client(dest, msg)
    print("############################")

main()