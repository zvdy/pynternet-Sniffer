import logging
import sys
from datetime import datetime

def setup_logging(log_to_terminal):
    """
    Set up logging to file and optionally to the terminal.
    """
    # Generate a timestamped log file name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f'network_activity_{timestamp}.log'

    # Set up logging to file
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s', handlers=[
        logging.FileHandler(log_file)
    ])

    if log_to_terminal:
        # Add console handler if terminal logging is enabled
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        logging.getLogger().addHandler(console_handler)