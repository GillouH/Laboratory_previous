from laboratoryTools.logging import logger, displayError


if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=displayError(error=e))