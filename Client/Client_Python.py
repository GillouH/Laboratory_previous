from socket import socket
from laboratoryTools.network import createSocket, serverAddress, serverAddressStr, checkInput, STOP_SERVER


STOP:str = "STOP"

server:socket = createSocket()
connected:bool = False
server.connect(serverAddress)
print("Connected to the server at {}".format(serverAddressStr))

clientLoop:bool = True
while clientLoop:
    msgToSend:str = checkInput(prompt="Message to send to the server at {}:\n\t_".format(serverAddressStr))
    if msgToSend == STOP:
        clientLoop = False
    else:
        server.send(msgToSend.encode())
        msgReceived:str = server.recv(1024).decode()
        print("Message received from the server at {}:\n\t{}".format(serverAddressStr, msgReceived))
        if msgToSend == STOP_SERVER and msgReceived == STOP_SERVER:
            print("The server at {} is shutting down.".format(serverAddressStr))
            clientLoop = False

print("Disconnecting from the server at {}".format(serverAddressStr))
server.close()