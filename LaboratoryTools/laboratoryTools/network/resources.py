from laboratoryTools.logging import logger, displayError
from os.path import dirname, join
from json import loads

filePath:"str" = join(dirname(__file__), "resources.json")

content:"str" = ""
with open(filePath, "r") as file:
    content = file.read()

resources:"dict[str,any]" = loads(s=content)
PORT:"int" = resources["PORT"]
PASSWORD:"str" = resources["PASSWORD"]

if __name__ == "__main__":
    try:
        pass
    except Exception as e:
        logger.error(msg=displayError(error=e))