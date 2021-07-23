from socket import socket, AF_INET, SOCK_STREAM
from laboratoryTools.network import serverAddress, serverAddressStr


MSG_CLIENT_DISCONNECTION:str = ""

server:socket = socket(family=AF_INET, type=SOCK_STREAM)
server.bind(serverAddress)
server.listen(5)
print("Server ready at {}".format(serverAddressStr))

client, infos = server.accept()
infos:str = "{}:{}".format(*infos)
print("Client connected: {}".format(infos))

serverLoop:bool = True
while serverLoop:
    msgReceived:str = client.recv(1024).decode()
    if msgReceived == MSG_CLIENT_DISCONNECTION:
        print("Client disconnected: {}".format(infos))
        client.close()
        serverLoop = False
    else:
        print("Message received from the client at {}:\n\t{}".format(infos, msgReceived))
        client.send(input("Reply to message from the client at {}:\n\t_".format(infos)).encode())

print("Server shutdown {}".format(serverAddress))
server.close()