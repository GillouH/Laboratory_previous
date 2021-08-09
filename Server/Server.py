from laboratoryTools.network import Socket, ServerSocket, ClientSocket, TIMEOUT, STOP_SERVER, PASSWORD
from laboratoryTools.logging import logger
from select import select
import rsa
from time import time
from laboratoryTools.securityManager import SecurityManager


class Server:
    def manageNewConnection(self):
        rList, wList, xList = select([self.serverSocket], [], [], TIMEOUT)
        for socketWaitingForConnection in rList:
            pubKey, privKey = rsa.newkeys(nbits=2048, poolsize=8)
            socketConnected, addr = socketWaitingForConnection.accept()
            clientSocket:"ClientSocket" = ClientSocket(socketSrc=socketConnected)
            logger.info(msg="Client connected {}".format(clientSocket))
            self.clientSocketList.append(clientSocket)
            clientSocket.pubKey, clientSocket.privKey = pubKey, privKey
            logger.info(msg="Sending RSA PUB KEY to {}".format(clientSocket))
            clientSocket.send(clientSocket.pubKey.save_pkcs1())
            clientSocket.timeStamp = time()

    def newClientFilter(self, clientSocket:"ClientSocket")->"bool":
        statutList:"[Socket.STATUT]" = [
            Socket.STATUT.NEW,
            Socket.STATUT.UNTRUSTED,
            Socket.STATUT.TRUSTED
        ]
        return clientSocket.statut in statutList

    def manageNewClientSocketMsg(self):
        clientSocketList:"[ClientSocket]" = list(filter(self.newClientFilter, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList, wList, xList = select(clientSocketList, [], [], TIMEOUT)
            for clientSocket in rList:
                try:
                    abort:bool = False
                    msgReceived:"str or bytes" = clientSocket.recv(1024) if clientSocket.key is None else SecurityManager.decrypt(text=clientSocket.recv(1024).decode(), key=clientSocket.key)
                    msgReceivedType:"type" = type(msgReceived)
                    if msgReceivedType == bytes:
                        if msgReceived == Socket.MSG_DISCONNECTION.encode():
                            abort = True
                        elif clientSocket.statut == Socket.STATUT.NEW:
                            logger.info(msg="Receiving KEY from {}".format(clientSocket))
                            try:
                                clientSocket.key = rsa.decrypt(crypto=msgReceived, priv_key=clientSocket.privKey).decode()
                            except Exception as e:
                                logger.error(msg=e)
                                abort = True
                            else:
                                clientSocket.statut = Socket.STATUT.UNTRUSTED
                                logger.info(msg="Ask PASSWORD to {}".format(clientSocket))
                                clientSocket.send(SecurityManager.encrypt(text=ServerSocket.ASK_PASSWORD, key=clientSocket.key, encoded=True))
                                clientSocket.timeStamp = time()
                        else:
                            abort = True
                    elif msgReceivedType == str:
                        if msgReceived == Socket.MSG_DISCONNECTION:
                            abort = True
                        elif clientSocket.statut == Socket.STATUT.UNTRUSTED and msgReceived == PASSWORD:
                            logger.info(msg="Receiving PASSWORD from {}".format(clientSocket))
                            clientSocket.statut = Socket.STATUT.TRUSTED
                            logger.info(msg="Ask name {}".format(clientSocket))
                            clientSocket.send(SecurityManager.encrypt(text=ServerSocket.ASK_NAME, key=clientSocket.key, encoded=True))
                            clientSocket.timeStamp = time()
                        elif clientSocket.statut == Socket.STATUT.TRUSTED:
                            logger.info(msg="Receiving name from {}".format(clientSocket))
                            clientSocket.name = msgReceived
                            clientSocket.statut = Socket.STATUT.OK
                            logger.info(msg="Client accepted {}".format(clientSocket))
                        else:
                            abort = True
                    else:
                        abort = True

                    if abort:
                        logger.info(msg="Client disconnected: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                except Exception as e:
                    logger.error(msg="{} {}".format(e, clientSocket))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    except Exception as e:
                        logger.error(msg="{} {}".format(e, clientSocket))

    def manageOKClientSocketMsg(self):
        clientSocketList = list(filter(lambda clientSocket: clientSocket.statut == Socket.STATUT.OK, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList, wList, xList = select(clientSocketList, [], [], TIMEOUT)
            for clientSocket in rList:
                try:
                    msgReceived:"str" = SecurityManager.decrypt(text=clientSocket.recv(1024).decode(), key=clientSocket.key)
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

    def manageClientSocketMsg(self):
        self.manageNewClientSocketMsg()
        self.manageOKClientSocketMsg()

    def checkClientSocketToDisconnect(self):
        def clientSocketToDisconnectFilter(clientSocket:"ClientSocket")->"bool":
            return self.newClientFilter(clientSocket=clientSocket) and clientSocket.timeStamp is not None and time() - clientSocket.timeStamp > ServerSocket.CONNECTION_TIMEOUT
        for clientSocket in filter(clientSocketToDisconnectFilter, self.clientSocketList):
            logger.info(msg="Client disconnected: {}".format(clientSocket))
            clientSocket.close()
            self.clientSocketList.remove(clientSocket)

    def start(self):
        self.serverSocket:"ServerSocket" = ServerSocket(name="Laboratory")
        logger.info(msg="Server ready {}".format(self.serverSocket))

        self.clientSocketList:"[ClientSocket]" = []
        self.loop:"bool" = True
        while self.loop:
            self.manageNewConnection()
            self.manageClientSocketMsg()
            self.checkClientSocketToDisconnect()

    def stop(self):
        for clientSocket in self.clientSocketList:
            try:
                logger.info(msg="Client disconnection: {}".format(clientSocket))
                if clientSocket.key is not None:
                    clientSocket.send(SecurityManager.encrypt(text=STOP_SERVER, key=clientSocket.key, encoded=True))
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