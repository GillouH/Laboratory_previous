from laboratoryTools.network import ServerSocket, ClientSocket, TIMEOUT, STOP_SERVER
from laboratoryTools.logging import logger
from select import select


class Server:
    MSG_CLIENT_DISCONNECTION:str = ""

    def manageNewConnection(self):
        rList, wList, xList = select([self.serverSocket], [], [], TIMEOUT)
        for socketWaitingForConnection in rList:
            socketConnected, addr = socketWaitingForConnection.accept()
            clientSocket:ClientSocket = ClientSocket(socketSrc=socketConnected)
            logger.info(msg="Client connected {}".format(clientSocket))
            self.clientSocketList.append(clientSocket)

    def manageClientSocketMsg(self):
        if len(self.clientSocketList) > 0:
            rList, wList, xList = select(self.clientSocketList, [], [], TIMEOUT)
            for clientSocketWithMsg in rList:
                try:
                    msgReceived:str = clientSocketWithMsg.recv(1024).decode()
                    if msgReceived == Server.MSG_CLIENT_DISCONNECTION:
                        logger.info(msg="Client disconnected: {}".format(clientSocketWithMsg))
                        clientSocketWithMsg.close()
                        self.clientSocketList.remove(clientSocketWithMsg)
                    elif msgReceived == STOP_SERVER:
                        self.loop = False
                    else:
                        logger.info(msg="Message received from the client {}:\n\t{}".format(clientSocketWithMsg, msgReceived))
                except Exception as e:
                    logger.error(msg="{} {}".format(e, clientSocketWithMsg))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocketWithMsg))
                        clientSocketWithMsg.close()
                        self.clientSocketList.remove(clientSocketWithMsg)
                    except Exception as e:
                        logger.error(msg="{} {}".format(e, clientSocketWithMsg))

    def start(self):
        self.serverSocket:ServerSocket = ServerSocket(name="Laboratory")
        logger.info(msg="Server ready {}".format(self.serverSocket))

        self.clientSocketList:list[ClientSocket] = []
        self.loop:bool = True
        while self.loop:
            self.manageNewConnection()
            self.manageClientSocketMsg()

    def stop(self):
        for clientSocket in self.clientSocketList:
            try:
                logger.info(msg="Client disconnection: {}".format(clientSocket))
                clientSocket.send(STOP_SERVER.encode())
                clientSocket.close()
            except Exception as e:
                logger.error(msg="{} {}".format(e, clientSocket))
        self.clientSocketList.clear()
        logger.info(msg="Server shutdown {}".format(self.serverSocket))
        self.serverSocket.close()


if __name__ == "__main__":
    try:
        server:Server = Server()
        server.start()
    except Exception as e:
        logger.error(msg=e)
    finally:
        server.stop()