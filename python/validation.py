#VALIDATION.py
import re

def validate_input(user_input):
    """
    Validates the user input to ensure it only contains alphanumeric characters and underscores.

    Args:
    user_input (str): The input string to validate.

    Returns:
    bool: True if the input is valid, False otherwise.
    """
    if re.match("^[a-zA-Z0-9_]+$", user_input):
        return True
    else:
        return False
