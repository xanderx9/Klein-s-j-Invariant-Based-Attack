import requests
import random
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from sympy import Mod

p = secp256k1.p
a, b = 0, 7

def klein_j_invariant(a, b, p):
    num = 1728 * (4 * a**3)
    den = (4 * a**3 + 27 * b**2)
    return None if den == 0 else Mod(num * pow(den, -1, p), p)

def generate_isomorphic_curve(a, b, p):
    while True:
        u = random.randint(1, p-1)
        a_new = Mod(a * u**4, p)
        b_new = Mod(b * u**6, p)
        if klein_j_invariant(a, b, p) == klein_j_invariant(a_new, b_new, p):
            return a_new, b_new

def extract_private_key(public_key, original_a, original_b):
    for _ in range(10000):
        a_iso, b_iso = generate_isomorphic_curve(original_a, original_b, p)
        if (a_iso, b_iso) == (original_a, original_b):
            with open("found.txt", "a") as f:
                f.write(f"{public_key.x},{public_key.y}\n")
            return (a_iso, b_iso)
    return None

def process_public_keys():
    try:
        with open("pub.txt", "r") as file:
            public_keys = file.readlines()
    except FileNotFoundError:
        print("[-] pub.txt file not found.")
        return

    for line in public_keys:
        line = line.strip()
        if len(line) < 130:
            continue
        try:
            public_key = Point(int(line[:64], 16), int(line[64:], 16), secp256k1)
            result = extract_private_key(public_key, a, b)
            if result:
                with open("found.txt", "a") as f:
                    f.write(f"Private Key Extracted: {result}\n")
                print(f"[✔] Vulnerability Found: {line}")
            else:
                print(f"[-] No Weakness: {line}")
        except:
            continue

process_public_keys()
