from django.contrib.auth.tokens import PasswordResetTokenGenerator
import random
import string
import secrets

class TokenGenerator(PasswordResetTokenGenerator):
    pass

generate_token = TokenGenerator()

def load_public_key(file_path):
    """This function loads the public key for the Apple NFC pass. It removes the begind and end section.

    Args:
        file_path (str): path of the public key

    Returns:
        str: Public key.
    """
    with open(file_path, 'r') as file:
        content = file.read()

        # Remove the beginning and ending lines
        content = content.replace("-----BEGIN PUBLIC KEY-----\n", "")
        content = content.replace("\n-----END PUBLIC KEY-----\n", "")
        content = content.replace("\n", "")  # Remove any newlines within the key

        return content


def generate_random_serial_number(length):
    """Generates a random unique serialnumber for NFC Passes.

    Args:
        length (int): It tells the length of the serialnumber.

    Returns:
        str: Serial number.
    """

    # Combines letters and digits
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))



def generate_random_message(max_length=64):
    """
    Generates a random hexadecimal message string suitable for NFC passes.

    This function creates a cryptographically strong random message that can be used as a payload in devices transmitting to Apple Pay terminals. The generated message is a hexadecimal string, ensuring compatibility and security for NFC communication.

    Args:
        max_length (int): The maximum length of the generated message in bytes. Default is 64 bytes.

    Returns:
        str: A random hexadecimal string of length up to the specified max_length. Each byte is represented by two hex digits, so the actual string length in characters will be twice the byte length.

    Example:
        >>> random_message = generate_random_message()
        >>> print(random_message)
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1...'

    Note:
        The function uses Python's `secrets` module for generating a cryptographically secure random string, making it suitable for sensitive applications like NFC passes for payment systems.
    """
    # Generate a token. Each byte is represented by two hex digits.
    token = secrets.token_hex(max_length // 2)
    return token

# Example usage
random_message = generate_random_message()
print(random_message)