"""
Sentinel NetLab - Detection Algorithms
Implements core detection logic and utilities.
"""

import hashlib


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def ssid_similarity(ssid1: str, ssid2: str) -> float:
    """
    Calculate similarity between two SSIDs (0.0 to 1.0).
    Using normalized Levenshtein distance.
    """
    if not ssid1 and not ssid2:
        return 1.0
    if not ssid1 or not ssid2:
        return 0.0

    dist = levenshtein_distance(ssid1, ssid2)
    max_len = max(len(ssid1), len(ssid2))

    if max_len == 0:
        return 1.0

    return 1.0 - (dist / max_len)


class BloomFilter:
    """
    Simple Bloom Filter implementation using hashlib.
    Does not depend on mmh3.
    """

    def __init__(self, size: int = 1000, hash_count: int = 3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [False] * size

    def add(self, item: str):
        for i in range(self.hash_count):
            index = self._get_hash(item, i)
            self.bit_array[index] = True

    def __contains__(self, item: str) -> bool:
        for i in range(self.hash_count):
            index = self._get_hash(item, i)
            if not self.bit_array[index]:
                return False
        return True

    def _get_hash(self, item: str, seed: int) -> int:
        """Generate hash index using SHA256 + seed suffix"""
        hash_val = hashlib.sha256(f"{item}{seed}".encode()).hexdigest()
        return int(hash_val, 16) % self.size
