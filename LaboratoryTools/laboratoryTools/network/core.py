from socket import getaddrinfo, gethostname, AF_INET
from laboratoryTools.network.resources import PORT
from laboratoryTools.logging import logger, displayError

def getIP()->"str":
    ip:"str" = "127.0.0.1"
    for addrInfo in getaddrinfo(host=gethostname(), port=None):
        if addrInfo[0] == AF_INET:
            ip:"str" = addrInfo[4][0]
            break
    return ip

IP:"str" = getIP()
serverAddress:"tuple[str,int]" = (IP, PORT)


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=displayError(error=e))