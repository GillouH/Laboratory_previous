from laboratoryTools.network import ServerSocket, ClientSocket
from laboratoryTools.logging import logger, displayError


class Server:
    def __init__(self, name):
        self.serverSocket:"ServerSocket" = ServerSocket(name=name)
        self.serverSocket.msgReceivedCallback = self.echoMsg

    def echoMsg(self, clientSocket:"ClientSocket", msg:"str"):
        logger.info(msg="Message receive from {}:\n\t{}".format(clientSocket, msg))
        clientSocket.send_s(data="I received \"{}\" from you.".format(msg))

    def start(self):
        self.serverSocket.start()

    def stop(self):
        self.serverSocket.stop()

if __name__ == "__main__":
    server:"Server" = Server(name="Laboratory")
    try:
        server.start()
    except Exception as e:
        logger.error(msg=displayError(error=e))
    finally:
        server.stop()