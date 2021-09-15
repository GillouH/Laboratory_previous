from socket import socket, AF_INET, SOCK_STREAM, dup, error
from typing import Union
from laboratoryTools.network.core import IP
from laboratoryTools.network.resources import PORT, PASSWORD
from laboratoryTools.logging import logger, displayError
from enum import Enum, auto
from select import select
import rsa
from time import time
from laboratoryTools.securityManager import SecurityManager
from threading import Thread


class Socket(socket):
    class STATUT(Enum):
        NEW = auto()    # is connected - waiting for key
        UNTRUSTED = auto()  # key known - waiting for password
        TRUSTED = auto()    # password checked - waiting for name
        OK = auto() # everything is checked

    CONNECTION_TIMEOUT:"float" = 1
    SELECT_TIMEOUT:"float" = 0.05
    MSG_DISCONNECTION:"str" = ""
    END_MSG:"str" = "\0"

    @classmethod
    def createSocket(cls)->"socket":
        return socket(family=AF_INET, type=SOCK_STREAM)

    def __init__(self, name:"str"=None, socketSrc:"socket"=None):
        # Make this class an bastract class
        if self.__class__ == Socket:
            raise TypeError("Can't instantiate abstract class {}".format(self.__class__.__qualname__))
        else:
            if socketSrc is None:
                socketSrc = Socket.createSocket()
            super().__init__(family=socketSrc.family, type=socketSrc.type, proto=socketSrc.proto, fileno=dup(socketSrc.fileno()))
            self.name:"Union[str,None]" = name
            self.statut:"Union[Socket.STATUT,None]" = None

    # méthode abstraite
    def getIPPort(self):
        raise NotImplementedError()

    def isClosed(self)->"bool":
        return self.fileno() == -1

    def __repr__(self)->"str":
        """Wrap __repr__() to reveal the real class name and socket
        address(es).
        """
        s:"str" = "<{} [{}]{}{} fd={}, family={}, type={}, proto={}".format(
            self.__class__.__qualname__,
            "close" if self.isClosed() else "open",
            "" if self.name is None else " name={}".format(self.name),
            "" if self.statut is None else " statut={}".format(self.statut.name),
            self.fileno(),
            self.family.__str__(),
            self.type.__str__(),
            self.proto.__str__()
        )
        if not self.isClosed():
            try:
                laddr:"tuple[str,int]" = self.getsockname()
                if laddr:
                    s += ", laddr={}".format(laddr)
            except error:
                pass
            try:
                raddr:"tuple[str,int]" = self.getpeername()
                if raddr:
                    s += ", raddr={}".format(raddr)
            except error:
                pass
        s += '>'
        return s

    def __str__(self)->"str":
        s:"str" = "[{}{}{}]".format(
            "" if self.name is None else "{} - ".format(self.name),
            "{}:{}".format(*self.getIPPort()),
            "" if self.statut is None else " - {}".format(self.statut.name)
        )
        return s

class ServerSocket(Socket):
    ASK_PASSWORD:"str" = "PASSWORD ?"
    ASK_NAME:"str" = "NAME ?"
    ACCEPTED:"str" = "ACCEPTED"
    STOP_SERVER:"str" = "STOP SERVER"

    def __init__(self, name:"str"=None):
        super().__init__(name=name)
        self.clientSocketList:"list[ClientSocket]" = []
        self.loop:"bool" = False

    def getIPPort(self)->"tuple[str,int]":
        return self.getsockname()

    def sendRSAPubKey(self, clientSocket:"ClientSocket"):
        clientSocket.pubKey, clientSocket.privKey = rsa.newkeys(nbits=2048, poolsize=8)
        logger.info(msg="Sending RSA PUB KEY to {}".format(clientSocket))
        clientSocket.send(clientSocket.pubKey.save_pkcs1())
        clientSocket.timeStamp = time()

    def manageNewConnection(self):
        rList:"list[socket]" = select([self], [], [], ServerSocket.SELECT_TIMEOUT)[0]
        for socketWaitingForConnection in rList:
            socketConnected:"socket" = socketWaitingForConnection.accept()[0]
            clientSocket:"ClientSocket" = ClientSocket(socketSrc=socketConnected)
            self.clientSocketList.append(clientSocket)
            logger.info(msg="Client connected {}".format(clientSocket))
            thread:"Thread" = Thread(target=self.sendRSAPubKey, kwargs={"clientSocket": clientSocket})
            thread.start()

    @classmethod
    def socketFilterByStatut(cls, clientSocket:"ClientSocket", statuts:"list[Socket.STATUT]")->bool:
        return clientSocket.statut in statuts

    @classmethod
    def newSocketFilter(cls, clientSocket:"ClientSocket")->"bool":
        statutList:"list[Socket.STATUT]" = [
            Socket.STATUT.NEW,
            Socket.STATUT.UNTRUSTED,
            Socket.STATUT.TRUSTED
        ]
        return cls.socketFilterByStatut(clientSocket=clientSocket, statuts=statutList)

    def manageNewClientSocketMsg(self):
        clientSocketList:"list[ClientSocket]" = list(filter(ServerSocket.newSocketFilter, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList:"list[ClientSocket]" = select(clientSocketList, [], [], ServerSocket.SELECT_TIMEOUT)[0]
            for clientSocket in rList:
                try:
                    abort:bool = False
                    msgReceived:"Union[bytes,list[str],str]" = clientSocket.recv(1024) if clientSocket.key is None else clientSocket.recv_s(bufferSize=1024)
                    if isinstance(msgReceived, bytes):
                        if msgReceived == Socket.MSG_DISCONNECTION.encode():
                            abort = True
                        elif clientSocket.statut == Socket.STATUT.NEW:
                            logger.info(msg="Receiving KEY from {}".format(clientSocket))
                            try:
                                clientSocket.key = rsa.decrypt(crypto=msgReceived, priv_key=clientSocket.privKey).decode()
                            except Exception as e:
                                logger.error(msg=displayError(error=e))
                                abort = True
                            else:
                                clientSocket.statut = Socket.STATUT.UNTRUSTED
                                logger.info(msg="Ask PASSWORD to {}".format(clientSocket))
                                clientSocket.send_s(data=ServerSocket.ASK_PASSWORD)
                                clientSocket.timeStamp = time()
                        else:
                            abort = True
                    elif isinstance(msgReceived, list) and len(msgReceived) == 1:
                        msgReceived = msgReceived[0]
                        if msgReceived == Socket.MSG_DISCONNECTION:
                            abort = True
                        elif clientSocket.statut == Socket.STATUT.UNTRUSTED and msgReceived == PASSWORD:
                            logger.info(msg="Receiving PASSWORD from {}".format(clientSocket))
                            clientSocket.statut = Socket.STATUT.TRUSTED
                            logger.info(msg="Ask name {}".format(clientSocket))
                            clientSocket.send_s(data=ServerSocket.ASK_NAME)
                            clientSocket.timeStamp = time()
                        elif clientSocket.statut == Socket.STATUT.TRUSTED:
                            logger.info(msg="Receiving name from {}".format(clientSocket))
                            clientSocket.name = msgReceived
                            clientSocket.statut = Socket.STATUT.OK
                            logger.info(msg="Client accepted {}".format(clientSocket))
                            clientSocket.send_s(data=ServerSocket.ACCEPTED)
                        else:
                            abort = True
                    else:
                        abort = True

                    if abort:
                        logger.info(msg="Client disconnected: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                except Exception as e:
                    logger.error(msg="{} {}".format(displayError(error=e), clientSocket))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    except Exception as e:
                        logger.error(msg="{} {}".format(displayError(error=e), clientSocket))

    def manageOKClientSocketMsg(self)->"bool":
        clientSocketList = list(filter(lambda clientSocket: clientSocket.statut == Socket.STATUT.OK, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList:"list[ClientSocket]" = select(clientSocketList, [], [], ServerSocket.SELECT_TIMEOUT)[0]
            for clientSocket in rList:
                try:
                    msgReceivedList:"list[str]" = clientSocket.recv_s(bufferSize=1024)
                    for msgReceived in msgReceivedList:
                        if msgReceived == Socket.MSG_DISCONNECTION:
                            logger.info(msg="Client disconnected: {}".format(clientSocket))
                            clientSocket.close()
                            self.clientSocketList.remove(clientSocket)
                        elif msgReceived == ServerSocket.STOP_SERVER:
                            self.loop = False
                            return False
                        elif msgReceived == ServerSocket.ASK_NAME:
                            clientSocket.send_s(data=self.name)
                        else:
                            self.msgReceivedCallback(clientSocket=clientSocket, msg=msgReceived)
                except Exception as e:
                    logger.error(msg="{} {}".format(displayError(error=e), clientSocket))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    except Exception as e:
                        logger.error(msg="{} {}".format(displayError(error=e), clientSocket))
        return True

    def manageClientSocketMsg(self)->"bool":
        self.manageNewClientSocketMsg()
        return self.manageOKClientSocketMsg()

    def checkClientSocketToDisconnect(self):
        def clientSocketToDisconnectFilter(clientSocket:"ClientSocket")->"bool":
            return ServerSocket.newSocketFilter(clientSocket=clientSocket) and clientSocket.timeStamp is not None and time() - clientSocket.timeStamp > ServerSocket.CONNECTION_TIMEOUT
        for clientSocket in filter(clientSocketToDisconnectFilter, self.clientSocketList):
            logger.info(msg="Client disconnected: {}".format(clientSocket))
            clientSocket.close()
            self.clientSocketList.remove(clientSocket)

    def start(self, ip:"str"=IP, port:"int"=PORT):
        self.bind((ip, port))
        self.listen(5)
        logger.info(msg="Server ready {}".format(self))

        self.loop = True
        while self.loop:
            self.manageNewConnection()
            if self.manageClientSocketMsg() == False:
                break
            self.checkClientSocketToDisconnect()

    def stop(self):
        for clientSocket in self.clientSocketList:
            try:
                logger.info(msg="Client disconnection: {}".format(clientSocket))
                if clientSocket.key is not None:
                    clientSocket.send_s(data=ServerSocket.STOP_SERVER)
                clientSocket.close()
            except Exception as e:
                logger.error(msg="{} {}".format(displayError(error=e), clientSocket))
        self.clientSocketList.clear()
        logger.info(msg="Server shutdown {}".format(self))
        self.close()

    def msgReceivedCallback(self, clientSocket:"ClientSocket", msg:"str"):
        raise NotImplementedError()


class ClientSocket(Socket):
    ConnectionUnableErrorMsg:"str" = "The connection to the server is impossible."

    def __init__(self, name:"str"=None, socketSrc:"socket"=None):
        super().__init__(name=None, socketSrc=socketSrc)
        self.localName:"Union[str,None]" = name
        self.statut:"Socket.STATUT" = Socket.STATUT.NEW
        self.pubKey:"Union[rsa.PublicKey,None]" = None
        self.privKey:"Union[rsa.PrivateKey,None]" = None
        self.key:"Union[str,None]" = None
        self.timeStamp:"Union[float,None]" = None

    def getIPPort(self)->"tuple[str,int]":
        return self.getpeername()

    def connect(self, address:"tuple[str,int]"):
        super().connect(address)
        errorCauseMsg = None
        def unknowError(errorCode:"int"):
            return "Unknown error. ({})".format(errorCode)
        serverShutDownErrorMsg = "Server has shut down."
        serverCloseConnectionErrorMsg = "Server closed the connection."
        abort, done = False, False
        accepted = False
        while not abort and not done and errorCauseMsg is None:
            if self.timeStamp is not None and time() - self.timeStamp > ClientSocket.CONNECTION_TIMEOUT:
                errorCauseMsg = "Server take too much time to respond."
                continue
            rList:"list[ClientSocket]" = select([self], [], [], ClientSocket.SELECT_TIMEOUT)[0]
            for socketWithMsg in rList:
                msgReceived:"Union[bytes,list[str]]" = socketWithMsg.recv(1024) if self.key is None else socketWithMsg.recv_s(bufferSize=1024)
                if isinstance(msgReceived, bytes):
                    if msgReceived.decode() in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                        if msgReceived.decode() == ServerSocket.STOP_SERVER:
                            errorCauseMsg = serverShutDownErrorMsg
                        elif msgReceived.decode() == Socket.MSG_DISCONNECTION:
                            errorCauseMsg = serverCloseConnectionErrorMsg
                    elif self.statut == Socket.STATUT.NEW:
                        logger.info(msg="Receiving RSA PUB KEY from {}".format(socketWithMsg))
                        try:
                            self.pubKey = rsa.PublicKey.load_pkcs1(keyfile=msgReceived)
                        except Exception as e:
                            logger.error(msg=displayError(error=e))
                            errorCauseMsg = "Enable to load RSA PUB KEY from server."
                        else:
                            self.key = SecurityManager.generateKey(nbChar=50)
                            logger.info(msg="Sending key to {}".format(socketWithMsg))
                            self.send(rsa.encrypt(message=self.key.encode(), pub_key=self.pubKey))
                            self.statut = Socket.STATUT.UNTRUSTED
                            self.timeStamp = time()
                    else:
                        errorCauseMsg = unknowError(errorCode=1)
                elif isinstance(msgReceived, list) and len(msgReceived) == 1:
                    msgReceived = msgReceived[0]
                    if msgReceived in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                        if msgReceived == ServerSocket.STOP_SERVER:
                            errorCauseMsg = serverShutDownErrorMsg
                        elif msgReceived == Socket.MSG_DISCONNECTION:
                            errorCauseMsg = serverCloseConnectionErrorMsg
                    elif self.statut == Socket.STATUT.UNTRUSTED:
                        if msgReceived == ServerSocket.ASK_PASSWORD:
                            logger.info(msg="Receiving PASSWORD request from {}".format(socketWithMsg))
                            logger.info(msg="Sending PASSWORD to {}".format(socketWithMsg))
                            self.send_s(data=PASSWORD)
                            self.statut = Socket.STATUT.TRUSTED
                            self.timeStamp = time()
                        else:
                            errorCauseMsg = "Server didn't ask for PASSWORD."
                    elif self.statut == Socket.STATUT.TRUSTED:
                        if msgReceived == ServerSocket.ASK_NAME:
                            logger.info(msg="Receiving name request from {}".format(socketWithMsg))
                            logger.info(msg="Sending name to {}".format(socketWithMsg))
                            self.send_s(data=self.localName)
                            self.statut = Socket.STATUT.OK
                            self.timeStamp = None
                        else:
                            errorCauseMsg = "Server didn't ask for name."
                    elif self.statut == Socket.STATUT.OK and not accepted:
                        if msgReceived == ServerSocket.ACCEPTED:
                            accepted = True
                            logger.info(msg="Ask name {}".format(socketWithMsg))
                            self.send_s(data=ServerSocket.ASK_NAME)
                        else:
                            errorCauseMsg = "Server didn't accept the connection."
                    elif self.statut == Socket.STATUT.OK:
                        logger.info(msg="Receiving name from {}".format(socketWithMsg))
                        self.name = msgReceived
                        logger.info(msg="Connected to {}".format(socketWithMsg))
                        done = True
                else:
                    errorCauseMsg = unknowError(errorCode=2)

        if errorCauseMsg is not None:
            errorMsg = "{}{} {}".format(ClientSocket.ConnectionUnableErrorMsg, " {}".format(errorCauseMsg), self)
            self.close()
            raise ConnectionError(errorMsg)

    def recv_s(self, bufferSize:"int")->"list[str]":
        if self.key is None:
            raise OSError("{}.{} can't be used until key argument is None. Use {} method instead.".format(self.__class__.__qualname__, self.recv_s.__name__, self.recv.__name__))
        msgReceived = SecurityManager.decrypt(text=self.recv(bufferSize).decode(), key=self.key)
        return [msgReceived] if msgReceived == Socket.MSG_DISCONNECTION else msgReceived.split(Socket.END_MSG)[:-1]

    def send_s(self, data:"str")->"int":
        if self.key is None:
            raise OSError("{}.{} can't be used until key argument is None. Use {} method instead.".format(self.__class__.__qualname__, self.send_s.__name__, self.send.__name__))
        return self.send(SecurityManager.encrypt(text=data+Socket.END_MSG, key=self.key, encoded=True))


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=displayError(error=e))