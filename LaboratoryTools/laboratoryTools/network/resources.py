from laboratoryTools.logging import logger, displayError
from os.path import dirname, join
from json import loads

FILE_PATH:"str" = join(dirname(__file__), "resources.json")

content:"str" = ""
with open(FILE_PATH, "r") as file:
    content = file.read()

RESOURCES:"dict[str,any]" = loads(s=content)

PORT:"int" = RESOURCES["PORT"]
PASSWORD:"str" = RESOURCES["PASSWORD"]

if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=displayError(error=e))