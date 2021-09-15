from laboratoryTools.logging import logger, displayError
from subprocess import check_call
from sys import executable
from importlib.util import find_spec
    

for module, installationName in [("tkinter", "python3-tk")]:
    if find_spec(name=module) is None:
        try:
            check_call(["sudo", "apt", "install", installationName])
        except Exception as e:
            logger.error(msg=displayError(error=e))


for module in ["rsa"]:
    if find_spec(name=module) is None:
        try:
            check_call([executable, "-m", "pip", "install", module])
        except Exception as e:
            logger.error(msg=displayError(error=e))