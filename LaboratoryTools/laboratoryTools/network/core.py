from socket import getaddrinfo, gethostname, socket, AF_INET, SOCK_STREAM
from laboratoryTools.network.resources import PORT


def getIP()->str:
    ip:str = "127.0.0.1"
    for family_, type_, proto_, canonname_, sockaddr_ in getaddrinfo(host=gethostname(), port=None):
        if family_ == AF_INET:
            ip, port_ = sockaddr_
            break
    return ip

IP:str = getIP()
serverAddress:tuple[str,int] = (IP, PORT)
serverAddressStr:str = "{}:{}".format(*serverAddress)

def createSocket()->socket:
    return socket(family=AF_INET, type=SOCK_STREAM)

def checkInput(prompt:str="")->str:
    text:str = input(prompt)
    while text == "":
        print("Please, enter a non empty value.")
        text = input(prompt)
    return text