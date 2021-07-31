from socket import socket
from laboratoryTools.network import createSocket, serverAddress, serverAddressStr, TIMEOUT, checkInput, STOP_SERVER
from laboratoryTools.log import logger
from select import select


MSG_CLIENT_DISCONNECTION:str = ""

def startServer():
    try:
        server:socket = createSocket()
        server.bind(serverAddress)
        server.listen(5)
        logger.info(msg="Server ready at {}".format(serverAddressStr))

        clientList:list[socket] = []
        serverLoop:bool = True
        while serverLoop:
            rlist, wList, xList = select([server], [], [], TIMEOUT)
            for newConnection in rlist:
                client, addr = newConnection.accept()
                logger.info(msg="Client connected: {}:{}".format(*addr))
                clientList.append(client)

            if len(clientList) > 0:
                rlist, wList, xList = select(clientList, [], [], TIMEOUT)
                for client in rlist:
                    try:
                        msgReceived:str = client.recv(1024).decode()
                        addr:tuple[str,int] = client.getpeername()
                        if msgReceived == MSG_CLIENT_DISCONNECTION:
                            logger.info(msg="Client disconnected: {}:{}".format(*addr))
                            client.close()
                            clientList.remove(client)
                        elif msgReceived == STOP_SERVER:
                            serverLoop = False
                        else:
                            logger.info(msg="Message received from the client at {}:{}:\n\t{}".format(*addr, msgReceived))
                    except Exception as e:
                        logger.error(msg=e)
                        try:
                            client.close()
                            clientList.remove(client)
                        except Exception as e:
                            logger.error(msg=e)

        for client in clientList:
            client.send(STOP_SERVER.encode())
            client.close()
        clientList.clear()

        logger.info(msg="Server shutdown {}".format(serverAddressStr))
        server.close()
    except:
        try:
            for client in clientList:
                client.send(STOP_SERVER.encode())
                client.close()
            clientList.clear()
        finally:
            logger.info(msg="Server shutdown {}".format(serverAddressStr))
            server.close()


if __name__ == "__main__":
    try:
        startServer()
    except Exception as e:
        looger.error(msg=e)