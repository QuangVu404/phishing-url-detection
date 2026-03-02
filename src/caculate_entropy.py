from collections import Counter
import math

def calculate_entropy(text: str) -> float:
    """
    Tính độ hỗn loạn Shannon Entropy của chuỗi.
    Chuỗi chứa nhiều ký tự ngẫu nhiên (lách luật, mã hóa) sẽ có điểm > 5
    """
    if not isinstance(text, str) or not text:
        return 0.0

    length = len(text)
    
    entropy = sum(
        -(count / length) * math.log2(count / length)
        for count in Counter(text).values()
    )

    return entropy