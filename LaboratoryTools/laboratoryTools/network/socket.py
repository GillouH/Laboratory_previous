from socket import socket, AF_INET, SOCK_STREAM, dup, error
from laboratoryTools.network.core import IP
from laboratoryTools.network.resources import PORT, PASSWORD
from laboratoryTools.logging import logger
from enum import Enum, auto
from select import select
import rsa
from time import time
from laboratoryTools.securityManager import SecurityManager


class Socket(socket):
    class STATUT(Enum):
        NEW = auto()    # is connected - waiting for key
        UNTRUSTED = auto()  # key known - waiting for password
        TRUSTED = auto()    # password checked - waiting for name
        OK = auto() # everything is checked

    CONNECTION_TIMEOUT:"float" = None
    SELECT_TIMEOUT:"float" = 0.05
    MSG_DISCONNECTION:"str" = ""

    @classmethod
    def createSocket(cls)->"socket":
        return socket(family=AF_INET, type=SOCK_STREAM)

    def __init__(self, name:"str"=None, socketSrc:"socket"=None)->"TypeError":
        # Make this class an bastract class
        if self.__class__ == Socket:
            raise TypeError("Can't instantiate abstract class {}".format(self.__class__.__qualname__))
        else:
            if socketSrc is None:
                socketSrc = Socket.createSocket()
            super().__init__(family=socketSrc.family, type=socketSrc.type, proto=socketSrc.proto, fileno=dup(socketSrc.fileno()))
            self.name:"str" = name
            self.statut:"STATUT" = None

    # méthode abstraite
    def getIPPort(self)->"NotImplementedError":
        raise NotImplementedError()

    def __repr__(self)->"str":
        """Wrap __repr__() to reveal the real class name and socket
        address(es).
        """
        s:"str" = "<{} [{}]{}{} fd={}, family={}, type={}, proto={}".format(
            self.__class__.__qualname__,
            "close" if self._closed else "open",
            "" if self.name is None else " name={}".format(self.name),
            "" if self.statut is None else " statut={}".format(self.statut.name),
            self.fileno(),
            str(object=self.family),
            str(object=self.type),
            str(object=self.proto)
            )
        if not self._closed:
            try:
                laddr:"(str,int)" = self.getsockname()
                if laddr:
                    s += ", laddr={}".format(laddr)
            except error:
                pass
            try:
                raddr:"(str,int)" = self.getpeername()
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
    CONNECTION_TIMEOUT:"float" = 1
    ASK_PASSWORD:"str" = "PASSWORD ?"
    ASK_NAME:"str" = "NAME ?"
    ACCEPTED:"str" = "ACCEPTED"
    STOP_SERVER:"str" = "STOP SERVER"

    def __init__(self, name:"str"=None):
        super().__init__(name=name)
        self.clientSocketList:"[ClientSocket]" = []
        self.loop:"bool" = False

    def getIPPort(self)->"(str,int)":
        return self.getsockname()

    def manageNewConnection(self):
        rList, wList, xList = select([self], [], [], ServerSocket.SELECT_TIMEOUT)
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

    @classmethod
    def socketFilterByStatut(cls, clientSocket:"ClientSocket", statuts:"[STATUT]")->bool:
        return clientSocket.statut in statuts

    @classmethod
    def newSocketFilter(cls, clientSocket:"ClientSocket")->"bool":
        statutList:"[Socket.STATUT]" = [
            Socket.STATUT.NEW,
            Socket.STATUT.UNTRUSTED,
            Socket.STATUT.TRUSTED
        ]
        return cls.socketFilterByStatut(clientSocket=clientSocket, statuts=statutList)

    def manageNewClientSocketMsg(self):
        clientSocketList:"[ClientSocket]" = list(filter(ServerSocket.newSocketFilter, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList, wList, xList = select(clientSocketList, [], [], ServerSocket.SELECT_TIMEOUT)
            for clientSocket in rList:
                try:
                    abort:bool = False
                    msgReceived:"str or bytes" = clientSocket.recv(1024) if clientSocket.key is None else clientSocket.recv_s(bufferSize=1024)
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
                                clientSocket.send_s(data=ServerSocket.ASK_PASSWORD)
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
                    logger.error(msg="{} {}".format(e, clientSocket))
                    try:
                        logger.info(msg="Client disconnection: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    except Exception as e:
                        logger.error(msg="{} {}".format(e, clientSocket))

    def manageOKClientSocketMsg(self)->"NotImplementedError":
        clientSocketList = list(filter(lambda clientSocket: clientSocket.statut == Socket.STATUT.OK, self.clientSocketList))
        if len(clientSocketList) > 0:
            rList, wList, xList = select(clientSocketList, [], [], ServerSocket.SELECT_TIMEOUT)
            for clientSocket in rList:
                try:
                    msgReceived:str = clientSocket.recv_s(bufferSize=1024)
                    if msgReceived == Socket.MSG_DISCONNECTION:
                        logger.info(msg="Client disconnected: {}".format(clientSocket))
                        clientSocket.close()
                        self.clientSocketList.remove(clientSocket)
                    elif msgReceived == ServerSocket.STOP_SERVER:
                        self.loop = False
                    elif msgReceived == ServerSocket.ASK_NAME:
                        clientSocket.send_s(data=self.name)
                    else:
                        self.msgReceivedCallback(clientSocket=clientSocket, msg=msgReceived)

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
            self.manageClientSocketMsg()
            self.checkClientSocketToDisconnect()

    def stop(self):
        for clientSocket in self.clientSocketList:
            try:
                logger.info(msg="Client disconnection: {}".format(clientSocket))
                if clientSocket.key is not None:
                    clientSocket.send_s(data=ServerSocket.STOP_SERVER)
                clientSocket.close()
            except Exception as e:
                logger.error(msg="{} {}".format(e, clientSocket))
        self.clientSocketList.clear()
        logger.info(msg="Server shutdown {}".format(self))
        self.close()

    def msgReceivedCallback(self, clientSocket:"ClientSocket", msg:"str")->"NotImplementedError":
        raise NotImplementedError


class ClientSocket(Socket):  
    CONNECTION_TIMEOUT:"float" = 10

    def __init__(self, name:"str"=None, socketSrc:"socket"=None):
        super().__init__(name=None, socketSrc=socketSrc)
        self.localName:"str" = name
        self.statut:"STATUT" = Socket.STATUT.NEW
        self.pubKey:"rsa.key.PublicKey" = None
        self.privKey:"rsa.key.PrivateKey" = None
        self.key:"str" = None
        self.timeStamp:"float" = None

    def getIPPort(self)->"(str,int)":
        return self.getpeername()

    def connect(self, address:"(str,int)"):
        super().connect(address)
        self.timeStamp = time()
        abort, done = False, False
        while not abort and not done:
            if self.timeStamp is not None and time() - self.timeStamp > ClientSocket.CONNECTION_TIMEOUT:
                abort = True
                continue
            rList, wList, xList = select([self], [], [], ClientSocket.SELECT_TIMEOUT)
            for socketWithMsg in rList:
                msgReceived:"str or bytes" = socketWithMsg.recv(1024) if self.key is None else socketWithMsg.recv_s(bufferSize=1024)
                msgReceivedType:"type" = type(msgReceived)
                if msgReceivedType == bytes:
                    if msgReceived.decode() in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                        abort = True
                    elif self.statut == Socket.STATUT.NEW:
                        logger.info(msg="Receiving RSA PUB KEY from {}".format(socketWithMsg))
                        try:
                            self.pubKey = rsa.key.PublicKey.load_pkcs1(keyfile=msgReceived)
                        except Exception as e:
                            logger.error(msg=e)
                            abort = True
                        else:
                            self.key = SecurityManager.generateKey(nbChar=50)
                            logger.info(msg="Sending key to {}".format(socketWithMsg))
                            self.send(rsa.encrypt(message=self.key.encode(), pub_key=self.pubKey))
                            self.statut = Socket.STATUT.UNTRUSTED
                            self.timeStamp = time()
                    else:
                        abort=True
                elif msgReceivedType == str:
                    if msgReceived in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                        abort = True
                    elif self.statut == Socket.STATUT.UNTRUSTED and msgReceived == ServerSocket.ASK_PASSWORD:
                        logger.info(msg="Receiving PASSWORD request from {}".format(socketWithMsg))
                        logger.info(msg="Sending PASSWORD to {}".format(socketWithMsg))
                        self.send_s(data=PASSWORD)
                        self.statut = Socket.STATUT.TRUSTED
                        self.timeStamp = time()
                    elif self.statut == Socket.STATUT.TRUSTED and msgReceived == ServerSocket.ASK_NAME:
                        logger.info(msg="Receiving name request from {}".format(socketWithMsg))
                        logger.info(msg="Sending name to {}".format(socketWithMsg))
                        self.send_s(data=self.localName)
                        self.statut = Socket.STATUT.OK
                        self.timeStamp = None
                    elif self.statut == Socket.STATUT.OK and msgReceived == ServerSocket.ACCEPTED:
                        logger.info(msg="Ask name {}".format(socketWithMsg))
                        self.send_s(data=ServerSocket.ASK_NAME)
                    elif self.statut == Socket.STATUT.OK:
                        logger.info(msg="Receiving name from {}".format(socketWithMsg))
                        self.name = msgReceived
                        logger.info(msg="Connected to {}".format(socketWithMsg))
                        done = True
                    else:
                        abort = True
                else:
                    abort = True
        if abort:
            self.close()
            raise ConnectionError("Enable to connect to the server.")

    def recv_s(self, bufferSize:"int")->"str":
        if self.key is None:
            raise OSError("{}.{} can't be used until key argument is None. Use {} method instead.".format(self.__class__.__qualname__, self.recv_s.__name__, self.recv.__name__))
        return SecurityManager.decrypt(text=self.recv(bufferSize).decode(), key=self.key)

    def send_s(self, data:"str")->"int":
        if self.key is None:
            raise OSError("{}.{} can't be used until key argument is None. Use {} method instead.".format(self.__class__.__qualname__, self.send_s.__name__, self.send.__name__))
        return self.send(SecurityManager.encrypt(text=data, key=self.key, encoded=True))


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=e)