from laboratoryTools.network import ServerSocket, ClientSocket, TIMEOUT, STOP_SERVER
from laboratoryTools.logging import logger
from select import select


MSG_CLIENT_DISCONNECTION:str = ""

def startServer():
    try:
        server:ServerSocket = ServerSocket("Laboratory")
        logger.info(msg="Server ready {}".format(server))

        clientList:list[ClientSocket] = []
        serverLoop:bool = True
        while serverLoop:
            rlist, wList, xList = select([server], [], [], TIMEOUT)
            for newConnection in rlist:
                client, addr = newConnection.accept()
                client:ClientSocket = ClientSocket(socketSrc=client)
                logger.info(msg="Client connected {}".format(client))
                clientList.append(client)

            if len(clientList) > 0:
                rlist, wList, xList = select(clientList, [], [], TIMEOUT)
                for client in rlist:
                    try:
                        msgReceived:str = client.recv(1024).decode()
                        if msgReceived == MSG_CLIENT_DISCONNECTION:
                            logger.info(msg="Client disconnected: {}".format(client))
                            client.close()
                            clientList.remove(client)
                        elif msgReceived == STOP_SERVER:
                            serverLoop = False
                        else:
                            logger.info(msg="Message received from the client {}:\n\t{}".format(client, msgReceived))
                    except Exception as e:
                        logger.error(msg="{} {}".format(e, client))
                        try:
                            client.close()
                            clientList.remove(client)
                        except Exception as e:
                            logger.error(msg="{} {}".format(e, client))

        for client in clientList:
            client.send(STOP_SERVER.encode())
            client.close()
        clientList.clear()

        logger.info(msg="Server shutdown {}".format(server))
        server.close()
    except Exception as e:
        logger.error(msg=e)
        try:
            for client in clientList:
                client.send(STOP_SERVER.encode())
                client.close()
            clientList.clear()
        finally:
            logger.info(msg="Server shutdown {}".format(server))
            server.close()


if __name__ == "__main__":
    try:
        startServer()
    except Exception as e:
        logger.error(msg=e)