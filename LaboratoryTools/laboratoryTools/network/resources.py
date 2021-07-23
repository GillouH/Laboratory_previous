from socket import getaddrinfo, gethostname, AF_INET


def getIP()->str:
    ip:str = "127.0.0.1"
    for family_, type_, proto_, canonname_, sockaddr_ in getaddrinfo(host=gethostname(), port=None):
        if family_ == AF_INET:
            ip, port_ = sockaddr_
            break
    return ip

# Server constant
IP:str = getIP()
PORT:int = 12800
serverAddress:tuple[str,int] = (IP, PORT)
serverAddressStr:str = "{}:{}".format(*serverAddress)