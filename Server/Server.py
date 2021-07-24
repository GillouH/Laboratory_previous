from socket import socket
from laboratoryTools.network import createSocket, serverAddress, serverAddressStr, TIMEOUT, checkInput, STOP_SERVER
from select import select


MSG_CLIENT_DISCONNECTION:str = ""

server:socket = createSocket()
server.bind(serverAddress)
server.listen(5)
print("Server ready at {}".format(serverAddressStr))

clientList:list[socket] = []
serverLoop:bool = True
while serverLoop:
    rlist, wList, xList = select([server], [], [], TIMEOUT)
    for newConnection in rlist:
        client, addr = newConnection.accept()
        print("Client connected: {}:{}".format(*addr))
        clientList.append(client)

    if len(clientList) > 0:
        rlist, wList, xList = select(clientList, [], [], TIMEOUT)
        for client in rlist:
            msgReceived:str = client.recv(1024).decode()
            addr:tuple[str,int] = client.getpeername()
            if msgReceived == MSG_CLIENT_DISCONNECTION:
                print("Client disconnected: {}:{}".format(*addr))
                client.close()
                clientList.remove(client)
            elif msgReceived == STOP_SERVER:
                serverLoop = False
            else:
                print("Message received from the client at {}:{}:\n\t{}".format(*addr, msgReceived))
                client.send(checkInput(prompt="Reply to message from the client at {}:{}:\n\t_".format(*addr)).encode())

for client in clientList:
    client.send(STOP_SERVER.encode())
    client.close()
clientList.clear()

print("Server shutdown {}".format(serverAddress))
server.close()