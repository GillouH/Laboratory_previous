from laboratoryTools.network import Socket, ServerSocket, ClientSocket, TIMEOUT, STOP_SERVER
from laboratoryTools.logging import logger
from select import select


class Server:
    def manageNewConnection(self):
        rList, wList, xList = select([self.serverSocket], [], [], TIMEOUT)
        for socketWaitingForConnection in rList:
            socketConnected, addr = socketWaitingForConnection.accept()
            clientSocket:"ClientSocket" = ClientSocket(socketSrc=socketConnected)
            logger.info(msg="Client connected {}".format(clientSocket))
            self.clientSocketList.append(clientSocket)

    def manageClientSocketMsg(self):
        if len(self.clientSocketList) > 0:
            rList, wList, xList = select(self.clientSocketList, [], [], TIMEOUT)
            for clientSocket in rList:
                try:
                    msgReceived:"str" = clientSocket.recv(1024).decode()
                    if msgReceived == Socket.MSG_DISCONNECTION:
                        logger.info(msg="Client disconnected: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    elif msgReceived == STOP_SERVER:
                        self.loop = False
                    else:
                        logger.info(msg="Message received from the client {}:\n\t{}".format(clientSocket, msgReceived))
                except Exception as e:
                    logger.error(msg="{} {}".format(e, clientSocket))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    except Exception as e:
                        logger.error(msg="{} {}".format(e, clientSocket))

    def start(self):
        self.serverSocket:"ServerSocket" = ServerSocket(name="Laboratory")
        logger.info(msg="Server ready {}".format(self.serverSocket))

        self.clientSocketList:"[ClientSocket]" = []
        self.loop:"bool" = True
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
        server:"Server" = Server()
        server.start()
    except Exception as e:
        logger.error(msg=e)
    finally:
        server.stop()