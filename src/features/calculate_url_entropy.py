from collections import Counter
import math

def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon Entropy of a string.
    Strings containing many random characters (obfuscation, encoding) will typically have a score > 5.
    """
    if not isinstance(text, str) or not text:
        return 0.0

    length = len(text)
    
    entropy = sum(
        -(count / length) * math.log2(count / length)
        for count in Counter(text).values()
    )

    return entropy