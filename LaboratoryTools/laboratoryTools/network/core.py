from socket import socket, AF_INET, SOCK_STREAM


def createSocket()->socket:
    return socket(family=AF_INET, type=SOCK_STREAM)

def checkInput(prompt:str="")->str:
    text:str = input(prompt)
    while text == "":
        print("Please, enter a non empty value.")
        text = input(prompt)
    return text