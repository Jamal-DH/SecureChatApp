#input_sanitization.py
def sanitize_input(user_input):
    """
    Sanitizes the user input by replacing certain characters with their HTML entity equivalents.

    Args:
    user_input (str): The input string to sanitize.

    Returns:
    str: The sanitized input string.
    """
    sanitized_input = user_input.replace('<', '&lt;').replace('>', '&gt;')
    return sanitized_input
