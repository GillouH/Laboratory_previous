from laboratoryTools.logging import logger


class SecurityManager:
    def __init__(self)->"TypeError":
        raise TypeError("Can't instantiate abstract class {}".format(self.__class__.__qualname__))

    @classmethod
    def generateKey(cls, nbChar:"int")->"str":
        # Personnal method to generate a random key.
        key:"str" = ""
        if nbChar < 1:
            logger.info(msg="Create an empty key.")
        else:
            pass
        return key

    @classmethod
    def encrypt(cls, text:"str", key:"str", encoded:"bool"=False)->"Union[str,bytes]":
        # Personnal method to encrypt some data.
        encryptedText:"str" = text
        return encryptedText if not encoded else encryptedText.encode()

    @classmethod
    def decrypt(cls, text:"str", key:"str", encoded:"bool"=False)->"Union[str,bytes]":
        # Personnal method to decrypt some data.
        decryptedText:"str" = text
        return decryptedText if not encoded else decryptedText.encode()


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=e)