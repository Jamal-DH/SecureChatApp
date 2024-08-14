import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(level=logging.DEBUG):
    log_dir = r"C:\Users\RTX\Desktop\SecureChatApp\python\logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'secure_chat.log')

    logger = logging.getLogger('secure_chat')
    logger.setLevel(level)

    file_handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=5)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
