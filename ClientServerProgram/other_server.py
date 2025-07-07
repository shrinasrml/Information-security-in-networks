from sympy import isprime
import random

def is_prime_solovay_strassen(n, k=1):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    def jacobi(a, n):
        if a == 0:
            return 0
        if a == 1:
            return 1
        if a % 2 == 0:
            s = -1 if n % 8 in (3, 5) else 1
            return s * jacobi(a // 2, n)
        if a > n:
            return jacobi(a % n, n)
        return -jacobi(n % a, a) if a % 4 == 3 and n % 4 == 3 else jacobi(n % a, a)

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = jacobi(a, n)
        if x == 0 or pow(a, (n - 1) // 2, n) != (x % n):
            return False

    return True


'''
def is_prime(n):
    """Проверка на простоту числа с использованием простого метода"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def find_large_prime():
    """Генерация большого простого числа"""
    while True:
        candidate = random.randint(2 ** 511, 2 ** 512 - 1)
        if is_prime(candidate) and is_prime((candidate - 1) // 2):
            return candidate


def get_divisors(n):
    """Получение всех делителей числа n"""
    divisors = []
    for i in range(1, int(n ** 0.5) + 1):
        if n % i == 0:
            divisors.append(i)
            if i != n // i:
                divisors.append(n // i)
    return divisors


def generate_diffie_hellman_parameters():
    """Генерация параметров для Диффи-Хеллмана с примитивным элементом"""

    def find_primitive_root(p):
        """Нахождение примитивного элемента для числа p"""
        # Получаем все делители p-1
        divisors = get_divisors(p - 1)
        # Перебираем возможные значения g
        for g in range(2, p):
            is_primitive = True
            for d in divisors:
                if d == 1:  # Пропускаем делитель 1
                    continue
                # Проверяем, что g^d % p != 1 для всех делителей
                if pow(g, d, p) == 1:
                    is_primitive = False
                    break
            if is_primitive:
                return g
        return None  # Не найден примитивный элемент

    # Генерация большого простого числа p
    p = find_large_prime()

    # Нахождение примитивного элемента g
    g = find_primitive_root(p)

    return p, g
'''
def generate_diffie_hellman_parameters():
    def find_large_prime():
        while True:
            candidate = random.randint(2**511, 2**512 - 1)
            if isprime(candidate) and isprime((candidate - 1) // 2):
                return candidate

    p = find_large_prime()
    g = random.randint(2, p - 1)
    return p, g

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    key = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)

def miller_rabin(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        if p % 2 != 0 and miller_rabin(p):
            return p

def mod_inverse(e, phi):
    original_phi = phi
    x0, x1 = 0, 1
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    return x1 + original_phi if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_rsa_keys(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def rsa_encrypt(message, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])


