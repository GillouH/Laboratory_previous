from laboratoryTools import ENCODING
from logging import StreamHandler, Formatter, FileHandler
from logging import DEBUG, INFO
from logging import getLogger

streamHandler = StreamHandler()
streamHandler.setLevel(level=DEBUG)
streamHandler.setFormatter(fmt=Formatter(fmt="{levelname} :: {funcName}(...) :: {message}", style="{"))

fileHandler = FileHandler(filename="info.log", mode="a", encoding=ENCODING)
fileHandler.setLevel(level=INFO)
fileHandler.setFormatter(fmt=Formatter(fmt="{asctime} :: {pathname} :: {levelname} :: {funcName}(...) :: {message}", style="{"))

logger = getLogger()
logger.setLevel(level=DEBUG)
logger.addHandler(hdlr=streamHandler)
logger.addHandler(hdlr=fileHandler)


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=e)