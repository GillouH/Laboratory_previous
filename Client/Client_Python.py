from socket import socket, AF_INET, SOCK_STREAM
from laboratoryTools.network import serverAddress, serverAddressStr


STOP:str = "STOP"

server:socket = socket(family=AF_INET, type=SOCK_STREAM)
connected:bool = False
server.connect(serverAddress)
print("Connected to the server at {}".format(serverAddressStr))

clientLoop:bool = True
while clientLoop:
    msgToSend:str = input("Message to send to the server at {}:\n\t_".format(serverAddressStr))
    if msgToSend == "":
        continue
    elif msgToSend == STOP:
        clientLoop = False
    else:
        server.send(msgToSend.encode())
        msgReceived:str = server.recv(1024).decode()
        print("Message received from the server at {}:\n\t{}".format(serverAddressStr, msgReceived))

print("Disconnecting from the server at {}".format(serverAddressStr))
server.close()