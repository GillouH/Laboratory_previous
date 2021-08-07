from socket import getaddrinfo, gethostname, AF_INET
from laboratoryTools.network.resources import PORT
from laboratoryTools.logging import logger

def getIP()->str:
    ip:str = "127.0.0.1"
    for family_, type_, proto_, canonname_, sockaddr_ in getaddrinfo(host=gethostname(), port=None):
        if family_ == AF_INET:
            ip, port_ = sockaddr_
            break
    return ip

IP:str = getIP()
serverAddress:tuple[str,int] = (IP, PORT)


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=e)