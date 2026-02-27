from collections import Counter
import math

def calculate_entropy(text):
    """
    Tính độ hỗn loạn Shannon Entropy của chuỗi.
    Chuỗi chứa nhiều ký tự ngẫu nhiên (lách luật, mã hóa) sẽ có điểm > 4.5
    """
    if not text:
        return 0
    entropy = 0
    for x in Counter(text).values():
        p_x = x / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy