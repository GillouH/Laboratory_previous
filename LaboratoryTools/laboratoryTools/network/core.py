from socket import getaddrinfo, gethostname, socket, AF_INET, SOCK_STREAM, dup, error
from laboratoryTools.network.resources import PORT
from laboratoryTools.logging import logger
from enum import Enum, auto

def getIP()->str:
    ip:str = "127.0.0.1"
    for family_, type_, proto_, canonname_, sockaddr_ in getaddrinfo(host=gethostname(), port=None):
        if family_ == AF_INET:
            ip, port_ = sockaddr_
            break
    return ip

IP:str = getIP()
serverAddress:tuple[str,int] = (IP, PORT)

class Socket(socket):
    MSG_DISCONNECTION:str = ""

    @classmethod
    def createSocket(cls)->socket:
        return socket(family=AF_INET, type=SOCK_STREAM)

    def __init__(self, name:str=None, socketSrc:socket=None)->TypeError:
        # Make this class an bastract class
        if self.__class__ == Socket:
            raise TypeError("Can't instantiate abstract class {}".format(self.__class__.__qualname__))
        else:
            if socketSrc is None:
                socketSrc = Socket.createSocket()
            super().__init__(family=socketSrc.family, type=socketSrc.type, proto=socketSrc.proto, fileno=dup(socketSrc.fileno()))
            self.name:str = name

    # méthode abstraite
    def getIPPort(self)->NotImplementedError:
        raise NotImplementedError()

    def __repr__(self)->str:
        """Wrap __repr__() to reveal the real class name and socket
        address(es).
        """
        s:str = "<{} [{}]{} fd={}, family={}, type={}, proto={}".format(
            self.__class__.__qualname__,
            "close" if self._closed else "open",
            " name={}".format(self.name) if self.name is not None else "",
            self.fileno(),
            str(object=self.family),
            str(object=self.type),
            str(object=self.proto)
            )
        if not self._closed:
            try:
                laddr:tuple[str,int] = self.getsockname()
                if laddr:
                    s += ", laddr={}".format(laddr)
            except error:
                pass
            try:
                raddr:tuple[str,int] = self.getpeername()
                if raddr:
                    s += ", raddr={}".format(raddr)
            except error:
                pass
        s += '>'
        return s

    def __str__(self)->str:
        s:str = "["
        s += "{}".format("{} - ".format(self.name) if self.name is not None else "")
        s += "{}:{}".format(*self.getIPPort())
        s += "]"
        return s

class ServerSocket(Socket):
    def __init__(self, name:str=None, ip:str=IP, port:int=PORT):
        super().__init__(name=name)
        self.bind((ip, port))
        self.listen(5)

    def getIPPort(self)->tuple[str,int]:
        return self.getsockname()

class ClientSocket(Socket):    
    def getIPPort(self)->tuple[str,int]:
        return self.getpeername()

if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=e)