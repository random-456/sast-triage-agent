import logging
import sys
import warnings
from langchain_core._api.deprecation import LangChainDeprecationWarning

def setup_logging(level=logging.INFO):
    """
    Sets up the logging configuration to be used inside the whole project.
    Logs will be sent only to the console.
    """
    # Get the root logger
    root_logger = logging.getLogger('')
    root_logger.setLevel(level)

    # Remove any existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure the console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)

    formatter = logging.Formatter('[%(levelname)s] %(name)s - %(message)s')
    console.setFormatter(formatter)

    # Add the console handler to the root logger
    root_logger.addHandler(console)

    # Hiding urllib3 logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Hiding langchain deprecation warning
    warnings.filterwarnings("ignore", category=LangChainDeprecationWarning)