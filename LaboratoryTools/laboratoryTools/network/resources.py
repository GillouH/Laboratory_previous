# Server constant
IP:str = "127.0.0.1"
PORT:int = 12800
serverAddress:tuple[str,int] = (IP, PORT)
serverAddressStr:str = "{}:{}".format(*serverAddress)