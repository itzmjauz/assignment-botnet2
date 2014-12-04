#!/usr/bin/python2.7
# also uses the pycrypto library
# written by Antoni Stevenet

import socket
import os
from Crypto.Cipher import ARC4  # pycrypto library for the encryption of creds

# init some usefull vars
opsys = bytearray('linux', 'utf-8')
hiByte = b'\x13'  # hey server!
hiOkByte = b'\x37'  # hi , whadup ?
recvCommand = b'\x14'  # could I have XXXXXX
command = b'\x39'  # sure man, here you go
received = b'\x16'  # thanks man, I got it.
recvconfirm = b'\x3a'  # cool, have fun with it
bye = b'\x17'  # well, see you then
byeok = b'\x3b'  # k, cya mate.
credentcmd = b'\x15'  # in case credentials gets called
cmdok = b'\xd1\x07\x00\x00'  # fukken nice cmd m8, kthxbye
sessionId = os.urandom(8)
key = ARC4.new(sessionId)  # grab our encryption key
secret = "skype=(johndoe,P4ssw0rd) gmail=(johndoe@gmail.com,plzD0ntH4xxorMe) checksum="


# port host
# HOST = "130.37.198.71"  # 'localhost' for server testing 
HOST = 'localhost'
PORT = 9999
# define functions


def process(recv):
    modifier = getModifier(recv)

    if modifier == hiOkByte:
        length = len(recvCommand) + len(sessionId) + 1
        mssg = bytearray(chr(length), 'utf') + recvCommand + sessionId

        global checksum
        checksum = getCheckSum(recv)

        print("checksum : " + checksum)  # print the checksum
        print(" ".join("{:02x}".format(ord(c))
                       for c in str(mssg)))  # print hex string

        s.send(mssg)
        print("sent confirmation ( ready to receive command )")

        return "hi"

    if modifier == command:
        cmd = getCommand(recv)
        return cmd

    if modifier == recvconfirm:
        return "rec"
    if modifier == byeok:
        return "bye"
    return


def getCheckSum(recv):
    s = recv[10:]
    return "".join("{:02x}".format(ord(c)) for c in s)


def getCredentials(recv):   # credentials for get_credentials
    credentials = secret + checksum
    encryptedD = key.encrypt(credentials)
    length = len(sessionId) + len(encryptedD) + len(credentcmd) + 1
    mssg = bytearray(chr(length), 'utf-8') + credentcmd + sessionId + encryptedD
    print(" ".join("{:02x}".format(ord(c)) for c in str(mssg)))
    s.send(mssg)


def grablink(recv, cmd):  # act as if we execute the command
    link = recv[11:]
    if cmd == "spam":
        print("spam downloading from: " + link)
    if cmd == "ddos":
        print("ddos-ing: " + link)
    if cmd == "install":
        print("installing badware from: " + link)


def getNthByte(i, recv):  # for ease of grabbing bytes from the bytestring
    return recv[(i - 1):i]


def getModifier(recv):  # for ease, again
    return getNthByte(2, recv)


def getCommand(recv):
    byte = getNthByte(11, recv)

    if byte == b'\x00':
        print "get-credentials command"
        getCredentials(recv)
        print "sent the credentials"
        return "hidden"

    if byte == b'\x01':
        grablink(recv, "install")
        return "install"

    if byte == b'\x02':
        grablink(recv, "ddos")
        return "ddos"

    if byte == b'\x03':
        grablink(recv, "spam")
        return "spam"

    else:
        print('nope')

# send the initial HI message to the server, ( with a random session-id)


def sendHi():
    length = len(hiByte) + len(sessionId) + len(opsys) + 1
    mssg = bytearray(chr(length), 'utf-8') + hiByte + sessionId + opsys
    print(" ".join("{:02x}".format(ord(c)) for c in str(mssg)))
    s.send(mssg)
    print("sent Hi message")

# connect + send HI message 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
sendHi()  # send hi message

# loop
while True:
    recv = s.recv(8192)
    print(" ".join("{:02x}".format(ord(c)) for c in recv))
    mod = process(recv)

    if mod == "ddos" or mod == "spam" or mod == "install" or mod == "hidden":
        length = len(received) + len(sessionId) + len(cmdok) + 1
        mssg = bytearray(chr(length), 'utf-8') + received + sessionId + cmdok

        print(" ".join("{:02x}".format(ord(c)) for c in str(mssg)))
        s.send(mssg)
        print("sent : command has been executed")

    if mod == "rec":
        length = len(bye) + len(sessionId) + 1
        mssg = bytearray(chr(length), 'utf-8') + bye + sessionId

        print("ok received")
        print(" ".join("{:02x}".format(ord(c)) for c in str(mssg)))
        s.send(mssg)
        print("bye sent")

    if mod == "bye":
        print("bye from server/connection closed")
        break
