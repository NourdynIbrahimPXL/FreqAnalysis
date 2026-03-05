#!/usr/bin/env python3
import math
import random
import re
import string
import sys
from collections import Counter

ENGLISH_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 1.0, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}

COMMON_WORDS = [
    "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", "as", "with",
    "was", "on", "be", "by", "this", "are", "or", "from", "at", "an", "not", "have",
    "had", "they", "you", "were", "their", "has", "would", "there", "what", "all",
    "can", "if", "we", "more", "when", "will", "one", "about", "which", "do", "out",
    "up", "who", "said", "been", "no", "into", "than", "them", "only", "could", "new",
    "other", "some", "these", "two", "first", "any", "like", "now", "such", "over",
    "our", "even", "most", "after", "also", "many", "did", "must", "before", "see",
    "through", "way", "where", "get", "much", "go", "well", "your", "should", "work",
    "because", "come", "people", "just", "those", "each", "good", "how", "long", "use",
    "very", "still", "between", "last", "never", "same", "while", "right", "might",
    "off", "find", "course", "fact", "internet", "students", "network", "university",
    "security", "reports", "public", "access", "upload", "college",
]
WORD_SCORE = {w: (len(COMMON_WORDS) - i) / len(COMMON_WORDS) for i, w in enumerate(COMMON_WORDS)}

LETTERS = string.ascii_lowercase
FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"

def frequency_analysis(text):
    letters = [c.lower() for c in text if c.isalpha()]
    counts = Counter(letters)
    total = sum(counts.values()) or 1
    print("Letter Frequency Analysis")
    print("-" * 38)
    print(f"{'Letter':<8}{'Count':<8}{'Percent'}")
    print("-" * 38)
    for ch, cnt in counts.most_common():
        print(f"{ch:<8}{cnt:<8}{(100 * cnt / total):.2f}%")
    print("-" * 38)
    print("Top 6 letters:", ", ".join([ch for ch, _ in counts.most_common(6)]))
    print()


def decrypt_caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def build_initial_key(ciphertext):
    cnt = Counter(c.lower() for c in ciphertext if c.isalpha())
    ranked_cipher = [c for c, _ in cnt.most_common()]
    mapping = {}
    for c, p in zip(ranked_cipher, FREQ_ORDER):
        mapping[c] = p
    remaining_cipher = [c for c in LETTERS if c not in mapping]
    remaining_plain = [c for c in LETTERS if c not in mapping.values()]
    for c, p in zip(remaining_cipher, remaining_plain):
        mapping[c] = p
    return mapping


def decrypt_substitution(text, mapping):
    out = []
    for ch in text:
        if ch.isalpha():
            p = mapping[ch.lower()]
            out.append(p.upper() if ch.isupper() else p)
        else:
            out.append(ch)
    return "".join(out)


def score_text(plain):
    tokens = re.findall(r"[a-z]+", plain.lower())
    if not tokens:
        return -1e9

    word_score = 0.0
    for t in tokens:
        if t in WORD_SCORE:
            word_score += 4.0 + 6.0 * WORD_SCORE[t]
        else:
            word_score -= 0.8 if len(t) > 2 else 0.2

    cnt = Counter(c for c in plain.lower() if c.isalpha())
    total = sum(cnt.values()) or 1
    chi = 0.0
    for ch in LETTERS:
        observed = cnt.get(ch, 0)
        expected = ENGLISH_FREQ[ch] / 100.0 * total
        if expected > 0:
            chi += ((observed - expected) ** 2) / expected

    return word_score - 0.03 * chi


def crack_substitution(ciphertext, restarts=25, iterations=8000):
    best_map = None
    best_plain = ""
    best_score = -1e18
    random.seed(1337)

    base_map = build_initial_key(ciphertext)

    for _ in range(restarts):
        cur = dict(base_map)
        for _ in range(150):
            a, b = random.sample(LETTERS, 2)
            cur[a], cur[b] = cur[b], cur[a]

        cur_plain = decrypt_substitution(ciphertext, cur)
        cur_score = score_text(cur_plain)

        for _ in range(iterations):
            a, b = random.sample(LETTERS, 2)
            cur[a], cur[b] = cur[b], cur[a]
            candidate = decrypt_substitution(ciphertext, cur)
            cand_score = score_text(candidate)

            if cand_score > cur_score or random.random() < 0.003:
                cur_plain, cur_score = candidate, cand_score
            else:
                cur[a], cur[b] = cur[b], cur[a]

            if cur_score > best_score:
                best_score = cur_score
                best_plain = cur_plain
                best_map = dict(cur)

    return best_plain, best_map, best_score


def crack_caesar(ciphertext):
    best_shift = 0
    best_text = ciphertext
    best_score = -1e18
    for shift in range(26):
        candidate = decrypt_caesar(ciphertext, shift)
        cand_score = score_text(candidate)
        if cand_score > best_score:
            best_score = cand_score
            best_text = candidate
            best_shift = shift
    return best_text, best_shift, best_score


def crack_cipher(ciphertext):
    caesar_text, shift, caesar_score = crack_caesar(ciphertext)
    sub_text, _, sub_score = crack_substitution(ciphertext)
    if sub_score >= caesar_score:
        return "monoalphabetic substitution", sub_text, sub_score
    return f"caesar shift ({shift})", caesar_text, caesar_score


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cipher_text = " ".join(sys.argv[1:])
    else:
        print("Paste ciphertext, then press Enter:")
        cipher_text = input().strip()

    frequency_analysis(cipher_text)
    cipher_type, plain_text, score = crack_cipher(cipher_text)
    print("Best Guess Type:", cipher_type)
    print("Score:", f"{score:.2f}")
    print("\nDecrypted Text:\n")
    print(plain_text)