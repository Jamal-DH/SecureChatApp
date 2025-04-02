# input_sanitization.py

def sanitize_input(user_input):
    """
    Sanitizes the user input by replacing certain characters with their HTML entity equivalents.
    
    This function helps prevent Cross-Site Scripting (XSS) attacks by escaping characters
    that could be interpreted as HTML or JavaScript when displayed in a web context.
    
    Args:
        user_input (str): The input string provided by the user that needs to be sanitized.
    
    Returns:
        str: The sanitized input string with potentially harmful characters escaped.
    """
    # Replace the less-than and greater-than symbols with their HTML entity equivalents
    sanitized_input = user_input.replace('<', '&lt;').replace('>', '&gt;')
    
    # Additional sanitization can be performed here if necessary
    
    return sanitized_input
