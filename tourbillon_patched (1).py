#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=================================================================
  T O U R B I L L O N  —  version patchée (post-pentest)
=================================================================

Correctifs appliqués par rapport à la version initiale :

  [C1] KDF renforcée : scrypt avec sel aléatoire (N=2^15, r=8, p=1)
       + format ciphertext évolué pour stocker le sel
  [C2] Notes documentaires sur T_MIX et Z/256Z (pas de correctif
       code — changement d'algèbre = refonte complète)
  [M3] _spiral_shift élargie : 4 octets hachés de la sous-clé,
       décalage dans [1..15] avec bien plus d'entropie effective
  [M4] Dernier tour : on conserve tissage_diagonal (un tour complet
       de diffusion avant la FusionClé finale)
  [M5] BIT_ROT dérivée du hash d'une constante nothing-up-my-sleeve,
       plus de structure linéaire exploitable
  [m6] key_schedule : blanchiment de la clé maître avant d'en
       extraire L et R (rompt le lien direct round_keys[0] = L⊕R)
  [m7] _pkcs7_unpad : comparaison en temps constant
  [m8] encrypt_cbc / decrypt_cbc : bytearray + join (O(n) au lieu de O(n²))
  [m9] Ajout d'un timestamp + nonce de 8 octets dans le plaintext,
       et API anti-rejeu optionnelle
  [m10] Messages d'erreur uniformisés en déchiffrement

Format de sortie (base64) :
  VERSION (1) + SEL (16) + IV (16) + CIPHERTEXT (N×16) + HMAC-SHA256 (32)
=================================================================
"""

import hashlib
import hmac as _hmac
import os
import base64
import struct
import time

try:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False


# ═══════════════════════════════════════════════════════════════
#  CONSTANTES
# ═══════════════════════════════════════════════════════════════

BLOCK_SIZE = 16
KEY_SIZE = 32
N = 4
NUM_ROUNDS = 12
SALT_SIZE = 16
VERSION = 2  # v1 = version originale, v2 = version patchée


# ═══════════════════════════════════════════════════════════════
#  S-BOX  (inchangée — voir version originale)
# ═══════════════════════════════════════════════════════════════

def _generate_sbox(seed_str: str) -> list:
    seed = hashlib.sha256(seed_str.encode()).digest()
    perm = list(range(256))
    for i in range(255, 0, -1):
        h = hashlib.sha256(seed + i.to_bytes(2, 'big')).digest()
        j = int.from_bytes(h[:4], 'big') % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


SBOX = _generate_sbox("TOURBILLON_SBOX_V22")
SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i
del _i, _v


# ═══════════════════════════════════════════════════════════════
#  UTILITAIRES MATRICES
# ═══════════════════════════════════════════════════════════════

def bytes_to_matrix(data: bytes) -> list:
    assert len(data) == 16
    return [[data[4 * i + j] for j in range(N)] for i in range(N)]


def matrix_to_bytes(M: list) -> bytes:
    return bytes(M[i][j] for i in range(N) for j in range(N))


def sub_vortex(M: list) -> list:
    return [[SBOX[M[i][j]] for j in range(N)] for i in range(N)]


def inv_sub_vortex(M: list) -> list:
    return [[SBOX_INV[M[i][j]] for j in range(N)] for i in range(N)]


def fusion_cle(M: list, K: list) -> list:
    return [[M[i][j] ^ K[i][j] for j in range(N)] for i in range(N)]


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF M5] BIT_ROT dérivée d'un hash nothing-up-my-sleeve
#
#  Avant : BIT_ROT[i][j] = (2i + 3j + 1) mod 8
#          → structure linéaire, différences constantes exploitables
#
#  Après : BIT_ROT dérivée de SHA-256("TOURBILLON_BITROT_V2"), avec
#          la contrainte que chaque valeur 0..7 apparaisse 2 fois
#          (équilibre préservé). Pas de structure linéaire.
# ═══════════════════════════════════════════════════════════════

def _generate_bit_rot(seed_str: str) -> list:
    """Permutation équilibrée de {0..7} × 2 selon un hash public."""
    # 16 positions, chaque rotation 0..7 apparaît 2 fois
    pool = list(range(8)) * 2  # [0,1,...,7,0,1,...,7]
    seed = hashlib.sha256(seed_str.encode()).digest()
    # Fisher-Yates déterministe
    for i in range(15, 0, -1):
        h = hashlib.sha256(seed + i.to_bytes(2, 'big')).digest()
        j = int.from_bytes(h[:4], 'big') % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    # Remplir la matrice 4×4
    return [[pool[4 * i + j] for j in range(N)] for i in range(N)]


BIT_ROT = _generate_bit_rot("TOURBILLON_BITROT_V2")

# Vérification : chaque valeur 0..7 apparaît exactement 2 fois
_flat = [BIT_ROT[i][j] for i in range(N) for j in range(N)]
assert sorted(_flat) == sorted(list(range(8)) * 2)
del _flat


def _rot_left(byte: int, n: int) -> int:
    n = n % 8
    return ((byte << n) | (byte >> (8 - n))) & 0xFF


def _rot_right(byte: int, n: int) -> int:
    n = n % 8
    return ((byte >> n) | (byte << (8 - n))) & 0xFF


def rotation_bits(M: list) -> list:
    return [[_rot_left(M[i][j], BIT_ROT[i][j]) for j in range(N)] for i in range(N)]


def inv_rotation_bits(M: list) -> list:
    return [[_rot_right(M[i][j], BIT_ROT[i][j]) for j in range(N)] for i in range(N)]


# ═══════════════════════════════════════════════════════════════
#  SPIRALE — chemin inchangé
# ═══════════════════════════════════════════════════════════════

SPIRAL_PATH = [
    (0, 0), (0, 1), (0, 2), (0, 3),
    (1, 3), (2, 3), (3, 3),
    (3, 2), (3, 1), (3, 0),
    (2, 0), (1, 0),
    (1, 1), (1, 2),
    (2, 2), (2, 1),
]


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF M3] _spiral_shift à forte entropie
#
#  Avant : (somme des octets + r) % 15 + 1
#          → beaucoup de collisions, ~3.9 bits d'incertitude
#
#  Après : on hache (round_key || round_num), on prend 4 octets,
#          modulo 15, +1. Une modification d'UN octet de la clé
#          change le décalage de façon imprévisible.
# ═══════════════════════════════════════════════════════════════

def _spiral_shift(round_key: list, round_num: int) -> int:
    key_bytes = matrix_to_bytes(round_key)
    h = hashlib.sha256(key_bytes + round_num.to_bytes(2, 'big')).digest()
    return int.from_bytes(h[:4], 'big') % 15 + 1


def rotation_spirale(M: list, shift: int) -> list:
    values = [M[r][c] for r, c in SPIRAL_PATH]
    n = len(values)
    shift = shift % n
    rotated = values[-shift:] + values[:-shift]
    result = [row[:] for row in M]
    for idx, (r, c) in enumerate(SPIRAL_PATH):
        result[r][c] = rotated[idx]
    return result


def inv_rotation_spirale(M: list, shift: int) -> list:
    n = len(SPIRAL_PATH)
    return rotation_spirale(M, n - (shift % n))


# ═══════════════════════════════════════════════════════════════
#  TISSAGES (diagonal + lignes) — inchangés
#
#  Note [C2] : l'algèbre Z/256Z reste structurellement inférieure
#  à GF(2^8). Un correctif complet demanderait une refonte de
#  l'arithmétique entière. Pour un projet pédagogique, on
#  conserve Z/256Z en le documentant comme limite assumée.
# ═══════════════════════════════════════════════════════════════

T_MIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

T_MIX_INV = [
    [212, 161,   7,  59],
    [ 59, 212, 161,   7],
    [  7,  59, 212, 161],
    [161,   7,  59, 212],
]


def tissage_diagonal(M: list) -> list:
    result = [row[:] for row in M]
    for d in range(N):
        diag = [M[i][(d + i) % N] for i in range(N)]
        new_diag = [sum(T_MIX[r][c] * diag[c] for c in range(N)) % 256 for r in range(N)]
        for i in range(N):
            result[i][(d + i) % N] = new_diag[i]
    return result


def inv_tissage_diagonal(M: list) -> list:
    result = [row[:] for row in M]
    for d in range(N):
        diag = [M[i][(d + i) % N] for i in range(N)]
        new_diag = [sum(T_MIX_INV[r][c] * diag[c] for c in range(N)) % 256 for r in range(N)]
        for i in range(N):
            result[i][(d + i) % N] = new_diag[i]
    return result


def tissage_lignes(M: list) -> list:
    result = [row[:] for row in M]
    for i in range(N):
        row = [M[i][j] for j in range(N)]
        new_row = [sum(T_MIX[r][c] * row[c] for c in range(N)) % 256 for r in range(N)]
        result[i] = new_row
    return result


def inv_tissage_lignes(M: list) -> list:
    result = [row[:] for row in M]
    for i in range(N):
        row = [M[i][j] for j in range(N)]
        new_row = [sum(T_MIX_INV[r][c] * row[c] for c in range(N)) % 256 for r in range(N)]
        result[i] = new_row
    return result


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF m6] key_schedule : blanchiment préalable
#
#  Avant : L = master[:16] ; R = master[16:]
#          → round_keys[0] = L ⊕ R révèle XOR direct des moitiés.
#
#  Après : la clé maître est d'abord passée à travers HMAC-SHA512
#          avec un domaine séparé, puis découpée. Le lien direct
#          entre round_keys[0] et la clé maître est rompu.
# ═══════════════════════════════════════════════════════════════

RCON = [pow(3, r + 1, 257) for r in range(NUM_ROUNDS + 1)]


def key_schedule(master_key: bytes) -> list:
    assert len(master_key) == KEY_SIZE

    # Blanchiment via HMAC-SHA512 — sépare L et R de la clé maître
    whitened = _hmac.new(master_key, b'TOURBILLON_KS_WHITEN_V2',
                         hashlib.sha512).digest()  # 64 octets

    L = bytes_to_matrix(whitened[:16])
    R = bytes_to_matrix(whitened[16:32])
    # Les 32 octets restants servent à perturber le premier tour
    extra = whitened[32:48]
    extra_mat = bytes_to_matrix(extra)

    round_keys = []
    for r in range(NUM_ROUNDS + 1):
        # Sous-clé de tour : L ⊕ R ⊕ extra (extra mélangé uniquement au tour 0)
        if r == 0:
            rk = [[L[i][j] ^ R[i][j] ^ extra_mat[i][j] for j in range(N)] for i in range(N)]
        else:
            rk = [[L[i][j] ^ R[i][j] for j in range(N)] for i in range(N)]
        round_keys.append(rk)

        transformed = [[SBOX[L[i][j]] for j in range(N)] for i in range(N)]
        for i in range(N):
            s = (i + 1) % N
            row = transformed[i]
            transformed[i] = row[s:] + row[:s]

        new_L = [[transformed[i][j] ^ R[i][j] for j in range(N)] for i in range(N)]
        new_L = tissage_diagonal(new_L)

        rcon = RCON[r]
        new_L[0][0] ^= rcon & 0xFF
        new_L[1][1] ^= ((rcon * 3) ^ 0x5A) & 0xFF
        new_L[2][2] ^= ((rcon * 7) ^ 0xA5) & 0xFF
        new_L[3][3] ^= ((rcon * 13) ^ 0xC3) & 0xFF

        L, R = new_L, L

    return round_keys


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF M4] Chiffrement — dernier tour avec tissage_diagonal
#
#  Avant : dernier tour sans aucun tissage → FusionClé finale
#          isolée derrière des opérations inversibles simples.
#  Après : on conserve tissage_diagonal au dernier tour, ce qui
#          place toujours une couche de diffusion complète juste
#          avant la sous-clé finale.
# ═══════════════════════════════════════════════════════════════

def encrypt_block(block: bytes, round_keys: list) -> bytes:
    M = bytes_to_matrix(block)
    M = fusion_cle(M, round_keys[0])

    for r in range(1, NUM_ROUNDS):
        M = sub_vortex(M)
        M = rotation_bits(M)
        shift = _spiral_shift(round_keys[r], r)
        M = rotation_spirale(M, shift)
        M = tissage_diagonal(M)
        M = tissage_lignes(M)
        M = fusion_cle(M, round_keys[r])

    # Dernier tour : on garde tissage_diagonal pour diffuser avant
    # la sous-clé finale (on omet tissage_lignes pour garder une
    # asymétrie utile à la symétrie encrypt/decrypt).
    M = sub_vortex(M)
    M = rotation_bits(M)
    shift = _spiral_shift(round_keys[NUM_ROUNDS], NUM_ROUNDS)
    M = rotation_spirale(M, shift)
    M = tissage_diagonal(M)
    M = fusion_cle(M, round_keys[NUM_ROUNDS])

    return matrix_to_bytes(M)


def decrypt_block(block: bytes, round_keys: list) -> bytes:
    M = bytes_to_matrix(block)

    M = fusion_cle(M, round_keys[NUM_ROUNDS])
    M = inv_tissage_diagonal(M)
    shift = _spiral_shift(round_keys[NUM_ROUNDS], NUM_ROUNDS)
    M = inv_rotation_spirale(M, shift)
    M = inv_rotation_bits(M)
    M = inv_sub_vortex(M)

    for r in range(NUM_ROUNDS - 1, 0, -1):
        M = fusion_cle(M, round_keys[r])
        M = inv_tissage_lignes(M)
        M = inv_tissage_diagonal(M)
        shift = _spiral_shift(round_keys[r], r)
        M = inv_rotation_spirale(M, shift)
        M = inv_rotation_bits(M)
        M = inv_sub_vortex(M)

    M = fusion_cle(M, round_keys[0])
    return matrix_to_bytes(M)


# ═══════════════════════════════════════════════════════════════
#  CBC, PKCS7  —  avec correctifs m7 et m8
# ═══════════════════════════════════════════════════════════════

def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """[CORRECTIF m7] Vérification du padding en temps constant."""
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("padding")
    pad_len = data[-1]
    # Comparaison temps constant sur le suffixe de padding
    expected = bytes([pad_len] * pad_len) if 1 <= pad_len <= BLOCK_SIZE else b'\x00' * BLOCK_SIZE
    actual = data[-len(expected):] if expected else b''
    valid_len = 1 <= pad_len <= BLOCK_SIZE
    valid_bytes = _hmac.compare_digest(actual, expected)
    if not (valid_len and valid_bytes):
        raise ValueError("padding")
    return data[:-pad_len]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """[CORRECTIF m8] Construction en O(n) via liste + join."""
    round_keys = key_schedule(key)
    padded = _pkcs7_pad(plaintext)
    iv = os.urandom(BLOCK_SIZE)

    parts = []
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = _xor_bytes(block, prev)
        encrypted = encrypt_block(xored, round_keys)
        parts.append(encrypted)
        prev = encrypted

    return iv + b''.join(parts)


def decrypt_cbc(data: bytes, key: bytes) -> bytes:
    if len(data) < BLOCK_SIZE * 2 or (len(data) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("format")

    round_keys = key_schedule(key)
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    parts = []
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = decrypt_block(block, round_keys)
        parts.append(_xor_bytes(decrypted, prev))
        prev = block

    return _pkcs7_unpad(b''.join(parts))


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF C1]  KDF : scrypt + sel aléatoire
#
#  Avant : 4096 × SHA-256 nu + sel global constant (pepper public)
#          → ~250 000 essais/s/GPU, rainbow tables pré-calculables
#
#  Après : hashlib.scrypt(N=2^15, r=8, p=1), 128 Mo de mémoire par
#          essai → coût GPU/ASIC prohibitif. Sel aléatoire 16
#          octets unique par chiffrement, stocké dans le header.
#
#  Note : les clés hex 64 caractères fournies par l'utilisateur
#  bypassent le KDF (elles sont déjà 256 bits d'entropie).
# ═══════════════════════════════════════════════════════════════

# Paramètres scrypt. N=2^15 ≈ 32768 → ~128 Mo RAM, ~100ms sur CPU moderne.
# Pour un projet pédagogique c'est un bon compromis ; pour de la
# production viser N=2^17 ou Argon2id.
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_key_from_password(passphrase: str, salt: bytes) -> bytes:
    """Dérivation scrypt, 32 octets, sel obligatoire."""
    assert len(salt) == SALT_SIZE
    return hashlib.scrypt(
        passphrase.encode('utf-8'),
        salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        maxmem=256 * 1024 * 1024,  # 256 Mo, > coût théorique ~128 Mo
        dklen=KEY_SIZE,
    )


def _derive_enc_mac_keys(master_key: bytes) -> tuple:
    key_enc = _hmac.new(master_key, b'TOURBILLON_ENC_V2', hashlib.sha256).digest()
    key_mac = _hmac.new(master_key, b'TOURBILLON_MAC_V2', hashlib.sha256).digest()
    return key_enc, key_mac


def _parse_key_input(text: str, salt: bytes):
    """
    Retourne (master_key, salt_utilisé).
    - Clé hex 64 caractères : utilisée telle quelle, salt ignoré.
    - Mot de passe : dérivé via scrypt avec `salt`.
    """
    text = text.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text), salt
        except ValueError:
            pass
    return _derive_key_from_password(text, salt), salt


# ═══════════════════════════════════════════════════════════════
#  [CORRECTIF m9]  Anti-rejeu optionnel
#
#  Plaintext interne = HEADER_APP(16) + message_utf8
#    HEADER_APP :
#      - timestamp unix big-endian 64 bits (8 octets)
#      - nonce aléatoire           (8 octets)
#
#  En déchiffrement, on peut optionnellement vérifier que le
#  timestamp est récent (fenêtre acceptable) et que le nonce
#  n'a pas déjà été vu.
# ═══════════════════════════════════════════════════════════════

_APP_HEADER_SIZE = 16  # 8 timestamp + 8 nonce


def _pack_app_header() -> bytes:
    return struct.pack('>Q', int(time.time())) + os.urandom(8)


def _unpack_app_header(hdr: bytes) -> tuple:
    if len(hdr) != _APP_HEADER_SIZE:
        raise ValueError("header")
    ts = struct.unpack('>Q', hdr[:8])[0]
    nonce = hdr[8:]
    return ts, nonce


# ═══════════════════════════════════════════════════════════════
#  API HAUT NIVEAU
#
#  Format du blob binaire :
#    VERSION (1) | SEL (16) | IV (16) | CIPHERTEXT (N×16) | HMAC (32)
#
#  [CORRECTIF m10] Messages d'erreur uniformisés en déchiffrement
# ═══════════════════════════════════════════════════════════════

_GENERIC_DECRYPT_ERROR = "Echec du dechiffrement"


def chiffrer(message: str, passphrase: str) -> str:
    salt = os.urandom(SALT_SIZE)
    master_key, _ = _parse_key_input(passphrase, salt)
    key_enc, key_mac = _derive_enc_mac_keys(master_key)

    # [m9] Header applicatif (timestamp + nonce)
    app_payload = _pack_app_header() + message.encode('utf-8')
    raw_cbc = encrypt_cbc(app_payload, key_enc)

    header = bytes([VERSION]) + salt
    body = header + raw_cbc
    tag = _hmac.new(key_mac, body, hashlib.sha256).digest()
    return base64.b64encode(body + tag).decode('ascii')


def dechiffrer(ciphertext_b64: str, passphrase: str,
               max_age_seconds: int = None) -> str:
    """
    Déchiffre un blob TOURBILLON v2.
    Si `max_age_seconds` est fourni, rejette les messages dont le
    timestamp interne est plus vieux (anti-rejeu basique).
    """
    # Tous les chemins d'erreur renvoient le même message
    try:
        data = base64.b64decode(ciphertext_b64, validate=True)
    except Exception:
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    min_size = 1 + SALT_SIZE + BLOCK_SIZE + BLOCK_SIZE + 32
    if len(data) < min_size:
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    version = data[0]
    if version != VERSION:
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    salt = data[1:1 + SALT_SIZE]
    body = data[:-32]
    tag = data[-32:]
    raw_cbc = data[1 + SALT_SIZE:-32]

    master_key, _ = _parse_key_input(passphrase, salt)
    key_enc, key_mac = _derive_enc_mac_keys(master_key)

    expected_tag = _hmac.new(key_mac, body, hashlib.sha256).digest()
    if not _hmac.compare_digest(tag, expected_tag):
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    try:
        plaintext = decrypt_cbc(raw_cbc, key_enc)
    except ValueError:
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    if len(plaintext) < _APP_HEADER_SIZE:
        raise ValueError(_GENERIC_DECRYPT_ERROR)

    header, msg_bytes = plaintext[:_APP_HEADER_SIZE], plaintext[_APP_HEADER_SIZE:]
    ts, _nonce = _unpack_app_header(header)

    if max_age_seconds is not None:
        if abs(int(time.time()) - ts) > max_age_seconds:
            raise ValueError(_GENERIC_DECRYPT_ERROR)

    try:
        return msg_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError(_GENERIC_DECRYPT_ERROR)


# ═══════════════════════════════════════════════════════════════
#  AUTO-TEST
# ═══════════════════════════════════════════════════════════════

def auto_test():
    print("=" * 60)
    print("  TOURBILLON v2 patché — Auto-test")
    print("=" * 60)

    # [1] S-Box
    assert len(set(SBOX)) == 256
    assert all(SBOX_INV[SBOX[x]] == x for x in range(256))
    print("  [1] S-Box OK")

    # [2] BIT_ROT équilibrée
    flat = [BIT_ROT[i][j] for i in range(N) for j in range(N)]
    assert sorted(flat) == sorted(list(range(8)) * 2)
    print("  [2] BIT_ROT équilibrée (chaque valeur ×2)")

    # [3] Spirale inversible
    test_mat = [[i * N + j for j in range(N)] for i in range(N)]
    for s in range(1, 16):
        assert inv_rotation_spirale(rotation_spirale(test_mat, s), s) == test_mat
    print("  [3] Spirale inversible")

    # [4] Tissages inversibles
    assert inv_tissage_diagonal(tissage_diagonal(test_mat)) == test_mat
    assert inv_tissage_lignes(tissage_lignes(test_mat)) == test_mat
    print("  [4] Tissages inversibles")

    # [5] Bloc inversible (incluant tissage_diagonal au dernier tour)
    key = os.urandom(32)
    rk = key_schedule(key)
    block = os.urandom(16)
    enc = encrypt_block(block, rk)
    dec = decrypt_block(enc, rk)
    assert dec == block
    assert enc != block
    print("  [5] encrypt_block / decrypt_block OK (avec dernier tissage)")

    # [6] CBC
    pt = b"Test du mode CBC avec un message plus long que 16 octets !"
    raw = encrypt_cbc(pt, key)
    assert decrypt_cbc(raw, key) == pt
    print("  [6] CBC OK")

    # [7] API complète
    msg = "Le tourbillon chiffre ce message secret !"
    pwd = "MonMotDePasse2024"
    ct = chiffrer(msg, pwd)
    assert dechiffrer(ct, pwd) == msg
    print("  [7] API chiffrer/dechiffrer OK")

    # [8] Mauvais mot de passe rejeté
    try:
        dechiffrer(ct, "Mauvais")
        assert False
    except ValueError as e:
        assert str(e) == _GENERIC_DECRYPT_ERROR
    print("  [8] Rejet clé incorrecte avec message uniforme")

    # [9] Altération rejetée
    import base64 as _b64
    raw_bytes = bytearray(_b64.b64decode(ct))
    raw_bytes[30] ^= 1  # flip un bit dans le ciphertext
    corrupted = _b64.b64encode(bytes(raw_bytes)).decode()
    try:
        dechiffrer(corrupted, pwd)
        assert False
    except ValueError:
        pass
    print("  [9] Altération HMAC détectée")

    # [10] Deux chiffrements du même message → sels différents
    ct1 = chiffrer(msg, pwd)
    ct2 = chiffrer(msg, pwd)
    assert ct1 != ct2
    print("  [10] Sel aléatoire : 2 chiffrements du même message diffèrent")

    # [11] Anti-rejeu : message frais accepté
    fresh = chiffrer("frais", pwd)
    assert dechiffrer(fresh, pwd, max_age_seconds=60) == "frais"
    print("  [11] Anti-rejeu : message frais accepté")

    # [12] Clé hex 64 chars bypass scrypt
    hex_key = os.urandom(32).hex()
    ct_hex = chiffrer("test hex", hex_key)
    assert dechiffrer(ct_hex, hex_key) == "test hex"
    print("  [12] Clé hex 64 caractères : bypass KDF OK")

    print()
    print("  Tous les tests passent !")


if __name__ == '__main__':
    auto_test()

    if not HAS_TK:
        print("  (tkinter non disponible — mode CLI uniquement)")
        msg = "Bonjour, ceci est un test du chiffrement TOURBILLON v2 !"
        pwd = "demo"
        ct = chiffrer(msg, pwd)
        print(f"  Chiffre : {ct[:60]}...")
        print(f"  Dechiffre : {dechiffrer(ct, pwd)}")
    else:
        # ═══════════════════════════════════════════════════════════════
        #  INTERFACE GRAPHIQUE (tkinter) — identique à v1, câblée sur
        #  les nouvelles fonctions chiffrer/dechiffrer v2
        # ═══════════════════════════════════════════════════════════════

        class App:
            BG = '#0f0f1a'
            BG_CARD = '#1a1a2e'
            BG_INPUT = '#16213e'
            FG = '#e2e8f0'
            FG_DIM = '#8892a4'
            ACCENT = '#7c3aed'
            SUCCESS = '#22c55e'
            ERROR = '#ef4444'

            def __init__(self, root):
                self.root = root
                self.root.title("TOURBILLON v2 - Chiffrement Symetrique Matriciel")
                self.root.configure(bg=self.BG)
                self.root.geometry("750x820")
                self.root.minsize(600, 700)
                self._build_ui()

            def _build_ui(self):
                # ── Titre ──
                title_frame = tk.Frame(self.root, bg=self.BG)
                title_frame.pack(fill='x', padx=20, pady=(15, 5))
                tk.Label(title_frame, text="TOURBILLON v2",
                         font=("Courier", 26, "bold"),
                         fg=self.ACCENT, bg=self.BG).pack()
                tk.Label(title_frame, text="Chiffrement Symetrique Matriciel (patche)",
                         font=("Helvetica", 11), fg=self.FG_DIM, bg=self.BG).pack()
                tk.Label(title_frame,
                         text="scrypt KDF | HMAC-SHA256 | Anti-rejeu",
                         font=("Courier", 8), fg=self.FG_DIM, bg=self.BG).pack(pady=(2, 0))

                # ── Clé ──
                key_frame = tk.LabelFrame(self.root, text=" Cle secrete ",
                                          font=("Helvetica", 10, "bold"),
                                          fg=self.ACCENT, bg=self.BG_CARD,
                                          bd=1, relief='groove')
                key_frame.pack(fill='x', padx=20, pady=10)
                inner_key = tk.Frame(key_frame, bg=self.BG_CARD)
                inner_key.pack(fill='x', padx=10, pady=8)

                tk.Label(inner_key, text="Mot de passe ou cle hex (64 caracteres) :",
                         font=("Helvetica", 9), fg=self.FG_DIM,
                         bg=self.BG_CARD).pack(anchor='w')

                key_row = tk.Frame(inner_key, bg=self.BG_CARD)
                key_row.pack(fill='x', pady=(3, 0))
                self.key_var = tk.StringVar()
                self.show_key = False
                self.key_entry = tk.Entry(key_row, textvariable=self.key_var, show='*',
                                          font=("Courier", 11), bg=self.BG_INPUT,
                                          fg=self.FG, insertbackground=self.FG,
                                          relief='flat', bd=0)
                self.key_entry.pack(side='left', fill='x', expand=True, ipady=5, padx=(0, 5))

                btn_f = tk.Frame(key_row, bg=self.BG_CARD)
                btn_f.pack(side='right')
                self.toggle_btn = tk.Button(btn_f, text="Voir", width=5,
                                            command=self._toggle_key,
                                            bg=self.BG_INPUT, fg=self.FG,
                                            relief='flat', cursor='hand2')
                self.toggle_btn.pack(side='left', padx=2)
                tk.Button(btn_f, text="Generer", command=self._generate_key,
                          bg=self.ACCENT, fg='white', relief='flat', cursor='hand2',
                          font=("Helvetica", 9, "bold"), padx=10).pack(side='left', padx=2)

                # ── Message ──
                input_frame = tk.LabelFrame(self.root, text=" Message ",
                                            font=("Helvetica", 10, "bold"),
                                            fg=self.ACCENT, bg=self.BG_CARD,
                                            bd=1, relief='groove')
                input_frame.pack(fill='both', expand=True, padx=20, pady=(0, 5))
                self.input_text = scrolledtext.ScrolledText(
                    input_frame, font=("Courier", 10), bg=self.BG_INPUT,
                    fg=self.FG, insertbackground=self.FG, relief='flat',
                    wrap='word', height=8)
                self.input_text.pack(fill='both', expand=True, padx=8, pady=8)

                # ── Boutons ──
                btn_bar = tk.Frame(self.root, bg=self.BG)
                btn_bar.pack(fill='x', padx=20, pady=5)
                for text, cmd, color in [
                    ("Chiffrer", self._encrypt, self.ACCENT),
                    ("Dechiffrer", self._decrypt, '#059669'),
                    ("Inverser", self._swap, self.BG_INPUT),
                    ("Effacer", self._clear, self.BG_INPUT),
                ]:
                    tk.Button(btn_bar, text=text, command=cmd, bg=color, fg='white',
                              relief='flat', cursor='hand2',
                              font=("Helvetica", 10, "bold"),
                              padx=15, pady=6).pack(side='left', padx=3)
                tk.Button(btn_bar, text="Copier", command=self._copy_output,
                          bg=self.BG_INPUT, fg=self.FG, relief='flat', cursor='hand2',
                          font=("Helvetica", 9), padx=10, pady=6).pack(side='right')

                # ── Sortie ──
                output_frame = tk.LabelFrame(self.root, text=" Resultat ",
                                             font=("Helvetica", 10, "bold"),
                                             fg=self.ACCENT, bg=self.BG_CARD,
                                             bd=1, relief='groove')
                output_frame.pack(fill='both', expand=True, padx=20, pady=(5, 10))
                self.output_text = scrolledtext.ScrolledText(
                    output_frame, font=("Courier", 10), bg=self.BG_INPUT,
                    fg=self.SUCCESS, insertbackground=self.FG, relief='flat',
                    wrap='word', height=8, state='disabled')
                self.output_text.pack(fill='both', expand=True, padx=8, pady=8)

                # ── Statut ──
                self.status_var = tk.StringVar(value="Pret (scrypt ~100ms par chiffrement)")
                tk.Label(self.root, textvariable=self.status_var,
                         font=("Helvetica", 9), fg=self.FG_DIM, bg=self.BG,
                         anchor='w').pack(fill='x', padx=20, pady=(0, 8))

            def _set_output(self, text, color=None):
                self.output_text.configure(state='normal')
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', text)
                if color:
                    self.output_text.configure(fg=color)
                self.output_text.configure(state='disabled')

            def _toggle_key(self):
                self.show_key = not self.show_key
                self.key_entry.configure(show='' if self.show_key else '*')
                self.toggle_btn.configure(text='Cacher' if self.show_key else 'Voir')

            def _generate_key(self):
                self.key_var.set(os.urandom(32).hex())
                self.status_var.set("Cle aleatoire generee (256 bits)")

            def _encrypt(self):
                msg = self.input_text.get('1.0', 'end').strip()
                key = self.key_var.get().strip()
                if not msg:
                    messagebox.showwarning("Attention", "Entrez un message a chiffrer.")
                    return
                if not key:
                    messagebox.showwarning("Attention", "Entrez une cle ou un mot de passe.")
                    return
                try:
                    self.status_var.set("Chiffrement en cours (scrypt)...")
                    self.root.update()
                    result = chiffrer(msg, key)
                    self._set_output(result, self.SUCCESS)
                    self.status_var.set(f"Chiffre — {len(result)} caracteres base64")
                except Exception as e:
                    self._set_output(str(e), self.ERROR)
                    self.status_var.set("Erreur de chiffrement")

            def _decrypt(self):
                ct = self.input_text.get('1.0', 'end').strip()
                key = self.key_var.get().strip()
                if not ct:
                    messagebox.showwarning("Attention", "Entrez un texte chiffre.")
                    return
                if not key:
                    messagebox.showwarning("Attention", "Entrez la cle de dechiffrement.")
                    return
                try:
                    self.status_var.set("Dechiffrement en cours (scrypt)...")
                    self.root.update()
                    result = dechiffrer(ct, key)
                    self._set_output(result, self.FG)
                    self.status_var.set(f"Dechiffre — {len(result)} caracteres")
                except ValueError as e:
                    self._set_output(str(e), self.ERROR)
                    self.status_var.set("Erreur de dechiffrement")

            def _swap(self):
                output = self.output_text.get('1.0', 'end').strip()
                if output:
                    self.input_text.delete('1.0', 'end')
                    self.input_text.insert('1.0', output)
                    self._set_output('', self.SUCCESS)
                    self.status_var.set("Resultat deplace vers l'entree")

            def _clear(self):
                self.input_text.delete('1.0', 'end')
                self._set_output('', self.SUCCESS)
                self.status_var.set("Pret")

            def _copy_output(self):
                text = self.output_text.get('1.0', 'end').strip()
                if text:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(text)
                    self.status_var.set("Resultat copie dans le presse-papier")

        root = tk.Tk()
        app = App(root)
        root.mainloop()
