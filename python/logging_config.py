import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(level=logging.DEBUG):
    # Get the absolute path of the directory where the current script is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the log directory relative to the base_dir
    log_dir = os.path.join(base_dir, 'logs')
    # Create the log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Define the full path to the log file
    log_file = os.path.join(log_dir, 'secure_chat.log')

    # Initialize a logger with the name 'secure_chat'
    logger = logging.getLogger('secure_chat')
    # Set the logging level for the logger
    logger.setLevel(level)

    # Create a rotating file handler that writes log messages to the log_file
    # It rotates the log file when it reaches 1MB and keeps up to 5 backup files
    file_handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=5)
    # Set the logging level for the file handler
    file_handler.setLevel(level)

    # Create a console handler to output log messages to the console
    console_handler = logging.StreamHandler()
    # Set the logging level for the console handler
    console_handler.setLevel(level)

    # Define the format for log messages
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Apply the formatter to the file handler
    file_handler.setFormatter(formatter)
    # Apply the formatter to the console handler
    console_handler.setFormatter(formatter)

    # Add the file handler to the logger
    logger.addHandler(file_handler)
    # Add the console handler to the logger
    logger.addHandler(console_handler)

    # Return the configured logger instance
    return logger
