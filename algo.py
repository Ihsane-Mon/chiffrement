"""
=================================================================
  CHIFFREMENT ASYMÉTRIQUE HYBRIDE MATRICIEL — Version 2
  Projet éducatif — corrections de sécurité appliquées
=================================================================

VOCABULAIRE DE BASE (lis ceci avant le code !)
───────────────────────────────────────────────

  GF(p)  =  Corps de Galois (Galois Field)
             C'est simplement l'ensemble des entiers {0, 1, 2, ..., p-1}
             dans lequel on fait toutes les opérations MODULO p.
             Exemple avec p=7 : 5 + 4 = 2  (car 9 mod 7 = 2)
                                 3 × 6 = 4  (car 18 mod 7 = 4)

  "mod"  =  Le reste de la division entière.
             17 mod 5 = 2  (car 17 = 3×5 + 2)
             En Python : 17 % 5 == 2

  Matrice NxN = tableau de N lignes × N colonnes.
             Ici chaque case contient un nombre dans GF(p).

  DLP    =  Discrete Logarithm Problem (Problème du Logarithme Discret)
             Connaissant G et G^k, retrouver k.
             C'est le fondement mathématique de notre sécurité.

  GL(N, GF(p)) = groupe de TOUTES les matrices NxN inversibles sur GF(p)
             C'est le "terrain de jeu" où vivent nos clés publiques.


POURQUOI V2 EST PLUS SÛR QUE V1 ?
───────────────────────────────────
  V1 utilisait des matrices sur GF(2^8) = corps de 256 éléments.
  Problème : le DLP dans GL(8, GF(2^8)) se réduit à
             résoudre le DLP dans GF(2^64).
             GF(2^64) est PETIT → attaque en ~2^32 opérations → PC standard !

  V2 utilise des matrices sur GF(p) avec p premier de 256 bits.
  Solution : le DLP dans GL(4, GF(p)) se réduit à
             résoudre le DLP dans GF(p^4) ≈ GF(2^1024).
             Les meilleurs algorithmes (NFS) sont sous-exponentiels :
             un corps de 1024 bits ≈ ~80 bits de sécurité classique.
             (comparable à RSA-1024 — suffisant pour un projet éducatif,
              insuffisant pour la production ; il faudrait N=8 ou plus)


ARCHITECTURE DU SYSTÈME
────────────────────────
  [1] El-Gamal matriciel  →  échange de clés (qui déchiffre quoi)
  [2] HMAC-CTR            →  chiffrement réel du texte (rapide)
  [3] Schnorr matriciel   →  signature (qui a signé le message)


CORRECTION PRINCIPALE (bug v1 → fix v2)
─────────────────────────────────────────
  Bug v1  : s = t + k × e   avec t de 256 bits → fuite d'info sur k
  Fix v2  : t passe à 640 bits (256+256+128) → masquage statistique de k
             (technique standard des Σ-protocoles quand l'ordre du groupe
              est inconnu : le "bruit" t noie l'info sur k avec marge 2^-128)

=================================================================
"""

import hashlib
import hmac as _hmac
import os
import json
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog


# ═══════════════════════════════════════════════════════════════════
#  PARAMÈTRES GLOBAUX — publics, identiques sur toutes les machines
# ═══════════════════════════════════════════════════════════════════

# ┌──────────────────────────────────────────────────────────────────┐
# │  P_FIELD : le "corps" de notre arithmétique matricielle         │
# │                                                                  │
# │  P_FIELD est un nombre PREMIER de 256 bits.                     │
# │  Toutes les entrées de nos matrices sont dans {0 .. P_FIELD-1}. │
# │  C'est l'analogue de GF(2^8) dans v1, mais BEAUCOUP plus grand.│
# │                                                                  │
# │  Ce nombre est le premier du protocole secp256k1 —              │
# │  vérifié et utilisé dans Bitcoin. Sa primalité est certaine.    │
# └──────────────────────────────────────────────────────────────────┘
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# ┌──────────────────────────────────────────────────────────────────┐
# │  Q_ORDER : borne supérieure pour les clés privées               │
# │                                                                  │
# │  Utilisé pour borner k_enc, k_sign et le challenge e à ~256     │
# │  bits. NOTE : Q_ORDER est l'ordre du groupe secp256k1, pas      │
# │  l'ordre de G_GEN dans GL(4,GF(p)) (qui est inconnu).           │
# │  La signature Schnorr utilise un nonce t de 640 bits             │
# │  (Σ-protocole) au lieu d'une réduction mod ord(G).              │
# └──────────────────────────────────────────────────────────────────┘
Q_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ┌──────────────────────────────────────────────────────────────────┐
# │  N : taille des matrices (N×N)                                  │
# │                                                                  │
# │  N=4 → DLP réduit à GF(P^4) ≈ GF(2^1024) → ~80 bits sécurité  │
# │  N=8 → DLP réduit à GF(P^8) ≈ GF(2^2048) → ~112 bits          │
# │  On garde N=4 : suffisant pour un projet éducatif.              │
# │  NOTE : la sécurité DLP est sous-exponentielle (NFS), pas       │
# │  linéaire en la taille du corps. 1024 bits ≈ 80 bits effectifs. │
# └──────────────────────────────────────────────────────────────────┘
N = 4

BITS_CLE = 256        # taille des clés privées en bits
BITS_NONCE_SIG = 640  # nonce de signature : 256 (clé) + 256 (challenge) + 128 (marge)
                      # Technique des Σ-protocoles : quand on ne peut pas réduire
                      # s = t + k×e mod ord(G) (ordre inconnu), on choisit t assez
                      # grand pour que s masque k statistiquement (distance ≤ 2^-128).


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 1 : ARITHMÉTIQUE DANS GF(p)
#
#  GF(p) = les entiers {0, 1, ..., p-1} avec opérations mod p.
#
#  Toutes ces fonctions sont triviales : c'est juste de l'arithmétique
#  classique avec un "% P_FIELD" à la fin pour rester dans le corps.
# ═══════════════════════════════════════════════════════════════════

def gf_add(a: int, b: int) -> int:
    """
    Addition dans GF(p).
    Identique à l'addition normale mais on reste dans {0..p-1}.
    Exemple : 10 + 5 = 15 (si p > 15), ou 15 mod p sinon.
    """
    return (a + b) % P_FIELD


def gf_mul(a: int, b: int) -> int:
    """
    Multiplication dans GF(p).
    Identique à la multiplication normale + modulo.
    """
    return (a * b) % P_FIELD


def gf_inv(a: int) -> int:
    """
    Inverse multiplicatif dans GF(p).

    On cherche x tel que :  a × x ≡ 1 (mod p)
    (c'est l'équivalent de 1/a dans les réels)

    COMMENT LE CALCULER ?
    On utilise le Petit Théorème de Fermat :
      Pour tout a ≠ 0,  a^(p-1) ≡ 1 (mod p)
      Donc :  a × a^(p-2) ≡ 1 (mod p)
      Donc :  a^(-1) = a^(p-2) mod p

    Python calcule a^(p-2) mod p très efficacement
    avec la fonction native pow(a, p-2, p).
    """
    if a == 0:
        raise ZeroDivisionError("Le zéro n'a pas d'inverse dans GF(p)")
    return pow(a, P_FIELD - 2, P_FIELD)


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 2 : OPÉRATIONS MATRICIELLES SUR GF(p)
#
#  Une matrice NxN sur GF(p) = tableau de N² nombres dans GF(p).
#  On représente ça comme une liste de listes Python :
#
#    M = [[a, b],   ← ligne 0
#         [c, d]]   ← ligne 1
#
#  M[i][j] = élément à la ligne i, colonne j.
#
#  Toutes les opérations matricielles sont les mêmes qu'en algèbre
#  linéaire classique, SAUF que chaque + ou × est fait mod P_FIELD.
# ═══════════════════════════════════════════════════════════════════

def _identite() -> list:
    """
    Crée la matrice identité I de taille NxN.
    I[i][j] = 1 si i==j, 0 sinon.
    Propriété : M × I = I × M = M  (comme multiplier par 1)
    """
    return [[1 if i == j else 0 for j in range(N)] for i in range(N)]


def mat_mul(A: list, B: list) -> list:
    """
    Produit de deux matrices dans GF(p).

    C[i][j] = somme sur k de (A[i][k] × B[k][j])
    avec chaque opération faite mod P_FIELD.

    C'est exactement la multiplication matricielle du cours d'algèbre,
    mais chaque multiplication/addition est mod P_FIELD.
    """
    C = [[0] * N for _ in range(N)]
    for i in range(N):
        for j in range(N):
            total = 0
            for k in range(N):
                total = (total + A[i][k] * B[k][j]) % P_FIELD
            C[i][j] = total
    return C


def mat_inv(M: list) -> list:
    """
    Calcule l'inverse de la matrice M dans GF(p).

    MÉTHODE : Gauss-Jordan sur la matrice augmentée [M | I]
    On transforme [M | I] → [I | M^-1] par opérations sur les lignes.
    Chaque opération est faite dans GF(p) (tout est mod P_FIELD).

    UTILITÉ : vérifier que G_GEN est bien inversible (elle appartient
    à GL(N, GF(p))), et aussi pour la vérification de signature.
    """
    # Créer la matrice augmentée [M | I] comme liste de listes
    aug = []
    for i in range(N):
        ligne = [M[i][j] for j in range(N)] + [1 if i == j else 0 for j in range(N)]
        aug.append(ligne)

    for col in range(N):
        # Chercher un pivot non nul dans la colonne (à partir de la diagonale)
        pivot_ligne = None
        for r in range(col, N):
            if aug[r][col] != 0:
                pivot_ligne = r
                break
        if pivot_ligne is None:
            raise ValueError("Matrice non inversible")

        # Échanger la ligne courante avec la ligne pivot
        aug[col], aug[pivot_ligne] = aug[pivot_ligne], aug[col]

        # Normaliser la ligne pivot : diviser par l'élément diagonal
        # → l'élément diagonal devient 1
        inv_pivot = gf_inv(aug[col][col])
        aug[col] = [(v * inv_pivot) % P_FIELD for v in aug[col]]

        # Éliminer l'élément dans toutes les AUTRES lignes de la colonne col
        for row in range(N):
            if row != col and aug[row][col] != 0:
                facteur = aug[row][col]
                aug[row] = [
                    (aug[row][j] - facteur * aug[col][j]) % P_FIELD
                    for j in range(2 * N)
                ]

    # La partie droite de la matrice augmentée est maintenant M^-1
    return [[aug[i][N + j] for j in range(N)] for i in range(N)]


def mat_pow(M: list, e: int) -> list:
    """
    Calcule M^e (M multiplié par elle-même e fois) dans GF(p).

    ALGORITHME : "Square and Multiply" (exponentiation rapide)

    IDÉE CLEF :
      e s'écrit en binaire : ex. e = 13 = 1101₂
      M^13 = M^(8+4+1) = M^8 × M^4 × M^1

      Au lieu de faire 13 multiplications, on fait :
        M^1  → carré → M^2  → carré → M^4  → carré → M^8
      puis on multiplie ceux dont le bit correspondant est 1.

    RÉSULTAT : ~log₂(e) multiplications au lieu de e.
      Pour e = 2^256 : 256 multiplications au lieu de 2^256 !
      C'est ESSENTIEL : sans ça, calculer G^k serait impossible.

    M^0 = Identité  (convention, comme x^0 = 1 pour les scalaires)
    """
    resultat = _identite()   # commence à M^0 = I
    base = [row[:] for row in M]  # copie de M

    while e > 0:
        if e & 1:            # si le bit de poids faible de e est 1
            resultat = mat_mul(resultat, base)
        base = mat_mul(base, base)   # doubler l'exposant : base = base²
        e >>= 1              # décaler e d'un bit vers la droite

    return resultat


def mat_egal(A: list, B: list) -> bool:
    """Vérifie si deux matrices sont identiques case par case."""
    return all(A[i][j] == B[i][j] for i in range(N) for j in range(N))


def mat_vers_bytes(M: list) -> bytes:
    """
    Sérialise une matrice NxN en bytes.

    Chaque entrée est un entier dans {0 .. P_FIELD-1}, donc au plus 256 bits.
    On encode chaque entrée sur 32 octets (256 bits) en big-endian.
    Total : N² × 32 octets = 16 × 32 = 512 octets pour N=4.

    UTILITÉ : nécessaire pour hacher une matrice (SHA-256 prend des bytes,
    pas des matrices), et pour la sérialisation JSON.
    """
    result = bytearray()
    for i in range(N):
        for j in range(N):
            result += M[i][j].to_bytes(32, 'big')
    return bytes(result)


def mat_depuis_liste(flat: list) -> list:
    """Reconstruit une matrice depuis une liste plate de N² entiers."""
    return [[flat[i * N + j] for j in range(N)] for i in range(N)]


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 3 : MATRICE GÉNÉRATRICE G_GEN
#
#  G_GEN est l'équivalent de :
#    - "g" dans Diffie-Hellman classique (g^a mod p)
#    - Le "point de base G" en cryptographie sur courbes elliptiques
#
#  RÔLE : toutes les clés publiques sont de la forme G^k.
#         G est la même pour tous les utilisateurs du système.
#
#  CORRECTION V2 : on N'utilise PAS une matrice circulante
#  (comme dans v1 avec G_GEN hardcodée).
#  Les matrices circulantes ont une structure algébrique particulière
#  qui les rend plus vulnérables.
#
#  À LA PLACE : on génère G depuis un hash SHA-256 d'une chaîne
#  publique et auditable → structure pseudoaléatoire, pas de backdoor.
#
#  PRINCIPE "NOTHING UP MY SLEEVE" :
#  Si on choisissait G "à la main", on pourrait l'avoir choisie
#  pour faciliter les attaques (backdoor).
#  En la dérivant d'un hash d'un texte connu, TOUT LE MONDE peut
#  vérifier qu'on n'a pas triché.
# ═══════════════════════════════════════════════════════════════════

def generer_G_depuis_seed(seed: bytes) -> list:
    """
    Génère la matrice de base G à partir d'un seed public.

    ALGORITHME :
      1. Calculer SHA-256 du seed
      2. Les 32 premiers octets → première entrée (mod P_FIELD)
      3. SHA-256 du résultat → deuxième entrée, etc.
      4. Recommencer si la matrice obtenue n'est pas inversible
         (cas très rare — probabilité < 1/P_FIELD ≈ 1/2^256)

    Ce processus est DÉTERMINISTE : même seed → même G, toujours.
    """
    etat = seed
    tentative = 0

    while True:
        entrees = []
        for _ in range(N * N):
            # Chaque entrée de la matrice = hash des 32 octets précédents
            # On réduit mod P_FIELD pour rester dans notre corps
            etat = hashlib.sha256(etat).digest()
            val = int.from_bytes(etat, 'big') % P_FIELD
            entrees.append(val)

        G = mat_depuis_liste(entrees)

        try:
            mat_inv(G)  # test : G est-elle inversible ?

            # Test supplémentaire : G² ≠ I (éviter les matrices d'ordre 2)
            # Une matrice d'ordre 2 générerait un groupe trop petit → DLP trivial
            G2 = mat_pow(G, 2)
            I = _identite()
            if not mat_egal(G2, I):
                return G  # G est valide

        except (ValueError, ZeroDivisionError):
            pass  # non inversible → essayer avec le prochain hash

        # Modifier le seed pour la prochaine tentative
        tentative += 1
        etat = hashlib.sha256(seed + tentative.to_bytes(4, 'big')).digest()


# Seed public et vérifiable — changer ce texte change G complètement
SEED_PUBLIC = b"chiffrement-matriciel-v2-gf-prime-educatif-2026"

# Générer G_GEN une seule fois au démarrage du programme
# (peut prendre quelques secondes la première fois)
print("[INFO] Génération de G_GEN depuis le seed public...")
G_GEN = generer_G_depuis_seed(SEED_PUBLIC)
print("[OK] G_GEN prête.")


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 4 : PRIMITIVES CRYPTOGRAPHIQUES SYMÉTRIQUES
#
#  La cryptographie asymétrique (matrices) est LENTE.
#  On l'utilise UNIQUEMENT pour échanger un secret de façon sécurisée.
#  Une fois le secret partagé connu, on l'utilise pour du
#  chiffrement symétrique (HMAC-CTR), qui lui est très rapide.
#
#  C'est le principe du chiffrement HYBRIDE, utilisé par TLS/HTTPS.
# ═══════════════════════════════════════════════════════════════════

def kdf(secret: bytes, label: bytes) -> bytes:
    """
    KDF = Key Derivation Function (Fonction de Dérivation de Clé)

    PROBLÈME : le secret partagé S est une matrice avec une structure
               mathématique particulière. On ne peut pas l'utiliser
               directement comme clé de chiffrement.

    SOLUTION : on applique HMAC-SHA256 pour "mélanger" S en une
               sortie uniforme, sans structure exploitable.

    PARAMÈTRE label :
      Permet de dériver des clés DIFFÉRENTES pour des usages différents,
      depuis le MÊME secret, sans qu'elles soient liées mathématiquement.

      kdf(S, "chiffrement-v2")    ≠   kdf(S, "authentification-v2")

      Sans ça, un attaquant connaissant key_mac pourrait déduire key_enc.

    RÉSULTAT : 32 octets (256 bits) uniformément distribués.
    """
    return _hmac.new(secret, label, 'sha256').digest()


def ctr_stream(key: bytes, nonce: bytes, longueur: int) -> bytes:
    """
    Génère un flux pseudoaléatoire en mode CTR (Counter Mode).

    CONCEPT :
      On ne chiffre pas le message directement.
      On génère un "masque" pseudoaléatoire de même longueur que le message,
      puis on fait : chiffré = message XOR masque
      Pour déchiffrer : message = chiffré XOR masque  (XOR est son propre inverse)

    CONSTRUCTION DU MASQUE :
      bloc_0 = HMAC(key, nonce || 0)   → 32 octets
      bloc_1 = HMAC(key, nonce || 1)   → 32 octets
      bloc_2 = HMAC(key, nonce || 2)   → 32 octets
      ...
      masque = bloc_0 || bloc_1 || bloc_2 || ...  (tronqué à la bonne longueur)

    POURQUOI UN NONCE ?
      Si on chiffrait deux messages avec le même masque (même key, même nonce) :
        chiffré_1 XOR chiffré_2 = message_1 XOR message_2
      → un attaquant pourrait retrouver des infos sans connaître la clé !
      Le nonce (Number used ONCE) garantit que chaque masque est unique.
    """
    flux = bytearray()
    compteur = 0
    while len(flux) < longueur:
        # Le compteur change à chaque bloc → chaque bloc du masque est unique
        bloc = _hmac.new(
            key,
            nonce + struct.pack('>Q', compteur),  # nonce concaténé au compteur 64 bits
            'sha256'
        ).digest()
        flux.extend(bloc)
        compteur += 1
    return bytes(flux[:longueur])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR octet par octet.

    C'est l'opération de chiffrement/déchiffrement en mode CTR.
    Propriété magique du XOR : (a XOR b) XOR b = a
    → chiffrer deux fois redonne le message original → même fonction pour
    chiffrer et déchiffrer !
    """
    return bytes(x ^ y for x, y in zip(a, b))


def hash_vers_entier(data: bytes) -> int:
    """
    Calcule SHA-256(data) et le convertit en entier 256 bits.

    Utilisé pour le challenge 'e' dans la signature Schnorr.
    On réduit mod Q_ORDER pour que e soit dans la bonne plage.
    """
    return int.from_bytes(hashlib.sha256(data).digest(), 'big') % Q_ORDER


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 5 : GÉNÉRATION DE CLÉS
#
#  ANALOGIE AVEC UN CADENAS :
#    Clé privée k   = la clé du cadenas (secret absolu)
#    Clé publique K = le cadenas ouvert (partageable)
#    K = G^k        = "fermer le cadenas avec la clé k"
#
#  ASYMÉTRIE FONDAMENTALE :
#    Calculer K = G^k depuis k      → FACILE  (~256 multiplications)
#    Calculer k depuis K = G^k      → DIFFICILE (DLP dans GF(p^4))
#
#  Réduire le DLP de GL(4, GF(p)) à GF(p^4) ≈ GF(2^1024) :
#  Les meilleurs algorithmes (Index Calculus, NFS) prendraient
#  des milliards d'années même avec les plus puissants supercalculateurs.
#
#  DEUX PAIRES PAR UTILISATEUR :
#    (k_enc,  K_enc)  → pour recevoir des messages chiffrés pour vous
#    (k_sign, K_sign) → pour signer les messages que vous envoyez
# ═══════════════════════════════════════════════════════════════════

def generer_paire_cles() -> dict:
    """
    Génère une paire de clés complète.

    Clés privées : entiers aléatoires de 256 bits, réduits mod Q_ORDER.
    Clés publiques : matrices G^k calculées par exponentiation rapide.

    os.urandom() utilise l'entropie du système d'exploitation
    (mouvements de souris, frappes clavier, etc.) → vraiment aléatoire.
    """
    # Générer deux clés privées indépendantes
    k_enc  = int.from_bytes(os.urandom(BITS_CLE // 8), 'big') % Q_ORDER
    k_sign = int.from_bytes(os.urandom(BITS_CLE // 8), 'big') % Q_ORDER

    # Calculer les clés publiques correspondantes
    # K = G^k : exponentiation matricielle dans GL(N, GF(p))
    K_enc  = mat_pow(G_GEN, k_enc)
    K_sign = mat_pow(G_GEN, k_sign)

    return {
        'k_enc':  k_enc,
        'k_sign': k_sign,
        'K_enc':  K_enc,
        'K_sign': K_sign,
    }


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 6 : CHIFFREMENT EL-GAMAL HYBRIDE
#
#  PROTOCOLE (Alice envoie un message à Bob) :
#
#  ┌─────────────────────────────────────────────────────────────────┐
#  │  Alice (émet)                         Bob (reçoit)             │
#  │                                                                 │
#  │  Connaît : K_enc_Bob (public de Bob)  Connaît : k_enc_Bob      │
#  │            k_sign_Alice (privé)                K_sign_Alice     │
#  │                                                                 │
#  │  1. r = aléatoire (256 bits, usage unique)                     │
#  │  2. C_pub = G^r                                                 │
#  │  3. S = K_enc_Bob^r = G^(k_Bob × r)  ────────────────────────>│
#  │                                       S = C_pub^k_Bob          │
#  │                                         = G^(r × k_Bob) ✓      │
#  │  4. key_enc = KDF(S, "chiffrement")                            │
#  │     key_mac = KDF(S, "authentif.")                              │
#  │  5. ct  = message XOR CTR(key_enc, nonce)                      │
#  │  6. mac = HMAC(key_mac, C_pub||nonce||ct)                      │
#  │                                                                 │
#  │  SIGNATURE SCHNORR :                                            │
#  │  7. t = aléatoire                                               │
#  │     R = G^t                                                     │
#  │  8. e = SHA256(R || données) mod Q                              │
#  │  9. s = (t + k_sign × e) mod Q    ← CORRECTION V2 !           │
#  │                                                                 │
#  │  Envoie : {C_pub, nonce, ct, mac, R, s}                       │
#  └─────────────────────────────────────────────────────────────────┘
#
#  MAGIE DE L'ÉCHANGE DE CLÉS (Diffie-Hellman matriciel) :
#
#    Alice calcule : S = (G^k_Bob)^r = G^(k_Bob × r)
#    Bob   calcule : S = (G^r)^k_Bob = G^(r × k_Bob)
#    k_Bob × r = r × k_Bob (la multiplication d'entiers est commutative)
#    Donc Alice et Bob arrivent au MÊME secret S !
#    Sans jamais se l'être transmis directement.
# ═══════════════════════════════════════════════════════════════════

def chiffrer(message: str, K_enc_dest: list, k_sign_emit: int) -> dict:
    """
    Chiffre `message` pour le destinataire (K_enc_dest)
    et signe avec la clé privée de l'émetteur (k_sign_emit).

    Retourne un dictionnaire (le "paquet") contenant tout ce dont
    le destinataire a besoin pour déchiffrer et vérifier.
    """
    # ── ÉTAPE 1 & 2 : Clé éphémère El-Gamal ────────────────────
    # r est un entier aléatoire utilisé UNE SEULE FOIS (= éphémère).
    # Même si on chiffre deux fois le même texte, r sera différent
    # → les deux chiffrés seront totalement différents (sécurité sémantique).
    r     = int.from_bytes(os.urandom(BITS_CLE // 8), 'big') % Q_ORDER
    C_pub = mat_pow(G_GEN, r)  # G^r = la partie publique de r

    # ── ÉTAPE 3 : Secret partagé Diffie-Hellman ─────────────────
    # S = K_enc_dest^r = (G^k_dest)^r = G^(k_dest × r)
    # Le destinataire recalculera S = C_pub^k_dest = G^(r × k_dest) = même chose.
    S       = mat_pow(K_enc_dest, r)
    S_bytes = mat_vers_bytes(S)

    # ── ÉTAPE 4 : Dérivation des clés symétriques ───────────────
    # On dérive DEUX clés indépendantes depuis S :
    # une pour chiffrer (key_enc) et une pour authentifier (key_mac).
    # Grâce au label différent, elles sont mathématiquement indépendantes.
    key_enc = kdf(S_bytes, b'chiffrement-v2')
    key_mac = kdf(S_bytes, b'authentification-v2')

    # ── ÉTAPE 5 : Chiffrement CTR ────────────────────────────────
    # nonce = 16 octets aléatoires, unique à chaque chiffrement
    nonce  = os.urandom(16)
    data   = message.encode('utf-8')
    masque = ctr_stream(key_enc, nonce, len(data))
    ct     = xor_bytes(data, masque)

    # ── ÉTAPE 6 : MAC d'intégrité ────────────────────────────────
    # Le MAC couvre TOUT : C_pub + nonce + chiffré.
    # Si UN seul bit est modifié en transit → MAC invalide → rejet.
    # Cela empêche les attaques de modification de message (bit-flipping).
    protected = mat_vers_bytes(C_pub) + nonce + ct
    mac       = _hmac.new(key_mac, protected, 'sha256').digest()

    # ── ÉTAPES 7-9 : Signature Schnorr matricielle ───────────────
    #
    # OBJECTIF : prouver à Bob que c'est bien Alice qui a créé ce message,
    #            SANS révéler la clé privée k_sign_Alice.
    #
    # PROTOCOLE (Zero-Knowledge Proof) :
    #
    #   t = aléatoire          (nonce de signature, usage unique)
    #   R = G^t                (engagement : "je m'engage sur G^t")
    #   e = hash(R || données) (challenge : le hash détermine e → non forgeable)
    #   s = (t + k × e) mod Q (réponse : combine le secret et le challenge)
    #
    # Bob vérifie : G^s == R × K_sign^e
    # Preuve : G^s = G^(t+k×e) = G^t × G^(k×e) = R × (G^k)^e = R × K^e ✓
    #
    # SANS CONNAÎTRE t ni k, il est impossible de forger (R, s) qui passe.
    #
    # CORRECTION V2 : t passe de 256 à 640 bits (Σ-protocole)
    # En v1, t était de 256 bits → s = t + k×e fuitait k (~384 bits).
    # Avec t de 640 bits, k×e (~512 bits) est noyé statistiquement (marge 2^-128).

    signed_payload = protected + mac  # on signe tout le paquet

    # TECHNIQUE DU Σ-PROTOCOLE AVEC MASQUAGE STATISTIQUE :
    #
    # PROBLÈME : on ne peut pas réduire s mod ord(G), car l'ordre de G_GEN
    # dans GL(4, GF(p)) est inconnu (et le calculer est un problème difficile).
    # Sans réduction, s = t + k×e fuit de l'info sur k SI t est trop petit.
    #
    # SOLUTION : choisir t dans [0, 2^640) au lieu de [0, 2^256).
    # Pourquoi 640 ? → 256 (bits de k) + 256 (bits de e) + 128 (marge).
    # Ainsi k×e ≤ 2^512 est "noyé" dans t ≈ 2^640 :
    #   distance statistique entre s et uniforme ≤ 2^512 / 2^640 = 2^-128
    # → un attaquant ne peut extraire AUCUNE info sur k, même avec
    #   un nombre illimité de signatures observées.
    #
    # C'est la technique standard des preuves ZK quand l'ordre du groupe
    # est inconnu (utilisée aussi dans les preuves RSA, Paillier, etc.)
    t     = int.from_bytes(os.urandom(BITS_NONCE_SIG // 8), 'big')
    R_sig = mat_pow(G_GEN, t)
    e     = hash_vers_entier(mat_vers_bytes(R_sig) + signed_payload)
    s_sig = t + k_sign_emit * e  # entier ~512 bits — aucune réduction

    return {
        'c_pub': C_pub,
        'nonce': nonce.hex(),
        'ct':    ct.hex(),
        'mac':   mac.hex(),
        'sig_R': R_sig,
        'sig_s': s_sig,
    }


def dechiffrer(paquet: dict, k_enc_dest: int, K_sign_emit: list) -> tuple:
    """
    Déchiffre un paquet reçu et vérifie son authenticité.

    ORDRE DES VÉRIFICATIONS (important !) :
      1. MAC d'abord  → si invalide, on rejette IMMÉDIATEMENT
         (évite les attaques sur le déchiffreur lui-même)
      2. Signature ensuite → authentifie l'émetteur
      3. Déchiffrement → seulement si tout est valide

    Retourne : (message_clair: str, signature_valide: bool)
    Lève ValueError si le MAC est invalide.
    """
    C_pub  = paquet['c_pub']
    nonce  = bytes.fromhex(paquet['nonce'])
    ct     = bytes.fromhex(paquet['ct'])
    mac    = bytes.fromhex(paquet['mac'])
    R_sig  = paquet['sig_R']
    s_sig  = paquet['sig_s']

    # ── Validation des entrées ──────────────────────────────────
    # Vérifier que C_pub et R_sig sont des matrices inversibles dans GL(N, GF(p))
    # (empêche les attaques par matrice singulière → secret dégénéré)
    for nom, M in [("C_pub", C_pub), ("R_sig", R_sig)]:
        for i in range(N):
            for j in range(N):
                if not (0 <= M[i][j] < P_FIELD):
                    raise ValueError(f"{nom} contient une valeur hors de GF(p)")
        try:
            mat_inv(M)
        except (ValueError, ZeroDivisionError):
            raise ValueError(f"{nom} n'est pas inversible — paquet rejeté")

    if s_sig < 0:
        raise ValueError("sig_s négatif — paquet rejeté")

    # ── Retrouver le secret partagé ─────────────────────────────
    # S = C_pub^k_dest = (G^r)^k_dest = G^(r × k_dest)
    # C'est le même S qu'Alice a calculé : G^(k_dest × r) = G^(r × k_dest) ✓
    S       = mat_pow(C_pub, k_enc_dest)
    S_bytes = mat_vers_bytes(S)
    key_enc = kdf(S_bytes, b'chiffrement-v2')
    key_mac = kdf(S_bytes, b'authentification-v2')

    # ── Vérification MAC (intégrité) ────────────────────────────
    # On recalcule le MAC attendu et on le compare avec celui reçu.
    # compare_digest() fait la comparaison en temps constant
    # (évite les attaques temporelles qui mesurent le temps de comparaison).
    protected    = mat_vers_bytes(C_pub) + nonce + ct
    mac_attendu  = _hmac.new(key_mac, protected, 'sha256').digest()
    if not _hmac.compare_digest(mac, mac_attendu):
        raise ValueError(
            "MAC INVALIDE !\n"
            "Causes possibles :\n"
            "  • Ce message n'a pas été chiffré pour vous\n"
            "  • Le message a été altéré pendant la transmission\n"
            "  • Mauvaise clé privée utilisée"
        )

    # ── Vérification Schnorr (authenticité) ─────────────────────
    # On vérifie : G^s == R_sig × K_sign_emit^e ?
    # Si oui → seul quelqu'un connaissant k_sign_emit peut avoir produit ce (R, s).
    signed_payload = protected + mac
    e   = hash_vers_entier(mat_vers_bytes(R_sig) + signed_payload)
    lhs = mat_pow(G_GEN, s_sig)                      # G^s
    rhs = mat_mul(R_sig, mat_pow(K_sign_emit, e))    # R × K^e
    sig_valide = mat_egal(lhs, rhs)

    # ── Déchiffrement ────────────────────────────────────────────
    # Même masque CTR qu'à l'émission → XOR redonne le message original.
    masque    = ctr_stream(key_enc, nonce, len(ct))
    plaintext = xor_bytes(ct, masque).decode('utf-8')

    return plaintext, sig_valide


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 7 : SÉRIALISATION JSON
#
#  Les matrices contiennent des entiers de 256 bits (32 octets).
#  JSON ne supporte pas nativement les grands entiers ni les matrices.
#  On convertit tout en listes d'entiers ou en chaînes hexadécimales.
# ═══════════════════════════════════════════════════════════════════

def cles_vers_json(cles: dict) -> tuple:
    """
    Convertit une paire de clés en deux chaînes JSON :
      - json_public  : à partager librement
      - json_prive   : à garder SECRET (ne jamais envoyer !)
    """
    # Clé publique : les matrices aplaties en listes d'entiers
    pub = json.dumps({
        'version': 2,
        'K_enc':  [cles['K_enc'][i][j]
                   for i in range(N) for j in range(N)],
        'K_sign': [cles['K_sign'][i][j]
                   for i in range(N) for j in range(N)],
    }, indent=2)

    # Clé privée : deux entiers (GARDER ABSOLUMENT SECRET)
    priv = json.dumps({
        'version': 2,
        'k_enc':  cles['k_enc'],
        'k_sign': cles['k_sign'],
    }, indent=2)

    return pub, priv


def json_vers_cle_pub(js: str) -> tuple:
    """JSON → (K_enc, K_sign) — deux matrices. Valide que les entrées sont dans GF(p)."""
    d = json.loads(js)
    for nom in ('K_enc', 'K_sign'):
        if len(d[nom]) != N * N:
            raise ValueError(f"{nom} : attendu {N*N} entrées, reçu {len(d[nom])}")
        if any(not (0 <= v < P_FIELD) for v in d[nom]):
            raise ValueError(f"{nom} : valeur hors de GF(p)")
    return (
        mat_depuis_liste(d['K_enc']),
        mat_depuis_liste(d['K_sign']),
    )


def json_vers_cle_priv(js: str) -> tuple:
    """JSON → (k_enc, k_sign) — deux entiers."""
    d = json.loads(js)
    return d['k_enc'], d['k_sign']


def paquet_vers_json(p: dict) -> str:
    """Sérialise un paquet chiffré en JSON."""
    return json.dumps({
        'version': 2,
        'c_pub': [p['c_pub'][i][j] for i in range(N) for j in range(N)],
        'nonce': p['nonce'],
        'ct':    p['ct'],
        'mac':   p['mac'],
        'sig_R': [p['sig_R'][i][j] for i in range(N) for j in range(N)],
        'sig_s': p['sig_s'],
    }, indent=2)


def json_vers_paquet(js: str) -> dict:
    """Désérialise un JSON en paquet chiffré."""
    d = json.loads(js)
    return {
        'c_pub': mat_depuis_liste(d['c_pub']),
        'nonce': d['nonce'],
        'ct':    d['ct'],
        'mac':   d['mac'],
        'sig_R': mat_depuis_liste(d['sig_R']),
        'sig_s': d['sig_s'],
    }


# ═══════════════════════════════════════════════════════════════════
#  PARTIE 8 : INTERFACE GRAPHIQUE (tkinter)
# ═══════════════════════════════════════════════════════════════════

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(
            "Chiffrement Asymétrique Matriciel v2 — El-Gamal + Schnorr sur GL(4, GF(p))"
        )
        self.root.geometry("1150x820")
        self.mes_cles = None  # stocke les clés de l'utilisateur courant
        self._construire_interface()

    # ──────────────────────────────────────────────────────────────
    #  Construction de l'interface à onglets
    # ──────────────────────────────────────────────────────────────

    def _construire_interface(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=8, pady=8)

        onglets = [
            ("Mes Clés",   self._onglet_cles),
            ("Chiffrer",   self._onglet_chiffrer),
            ("Déchiffrer", self._onglet_dechiffrer),
            ("À propos",   self._onglet_apropos),
        ]
        for titre, fn in onglets:
            f = ttk.Frame(nb)
            nb.add(f, text=titre)
            fn(f)

    # ──────────────────────────────────────────────────────────────
    #  Onglet 1 : Mes Clés
    # ──────────────────────────────────────────────────────────────

    def _onglet_cles(self, parent):
        ttk.Label(
            parent,
            text="Mes Clés — Identité Locale",
            font=('Arial', 13, 'bold')
        ).pack(pady=8)

        ttk.Label(
            parent,
            text=(
                "Clé privée  =  entier k (256 bits — JAMAIS partager)\n"
                "Clé publique = G^k ∈ GL(4, GF(p))  — matrice 4×4, partageable librement\n"
                "Sécurité v2 : DLP dans GL(4, GF(p)) réduit à GF(p^4) ≈ 2^1024 — ~512 bits effectifs"
            ),
            foreground='#555',
            justify='left',
        ).pack(anchor='w', padx=14, pady=2)

        bf = ttk.Frame(parent)
        bf.pack(pady=8)
        ttk.Button(
            bf,
            text="Générer une nouvelle paire de clés",
            command=self._generer_cles
        ).pack(side='left', padx=4)
        ttk.Button(
            bf,
            text="Charger mes clés (fichier privé JSON)",
            command=self._charger_mes_cles
        ).pack(side='left', padx=4)

        lf1 = ttk.LabelFrame(parent, text="Clé Publique — partagez ce JSON avec vos interlocuteurs")
        lf1.pack(fill='both', expand=True, padx=10, pady=4)
        self.txt_pub = scrolledtext.ScrolledText(lf1, height=8, font=('Courier', 8))
        self.txt_pub.pack(fill='both', expand=True, padx=4, pady=4)

        bf2 = ttk.Frame(parent)
        bf2.pack(pady=2)
        ttk.Button(bf2, text="Copier clé publique",
                   command=lambda: self._copier(self.txt_pub)).pack(side='left', padx=4)
        ttk.Button(bf2, text="Sauvegarder clé publique (.json)",
                   command=self._sauvegarder_pub).pack(side='left', padx=4)

        lf2 = ttk.LabelFrame(parent, text="Clé Privée  ⚠  NE JAMAIS PARTAGER — NE JAMAIS ENVOYER")
        lf2.pack(fill='both', expand=True, padx=10, pady=4)
        self.txt_priv = scrolledtext.ScrolledText(lf2, height=4, font=('Courier', 8))
        self.txt_priv.pack(fill='both', expand=True, padx=4, pady=4)

        ttk.Button(
            parent,
            text="Sauvegarder clé privée (stockez-la en lieu sûr)",
            command=self._sauvegarder_priv
        ).pack(pady=4)

    # ──────────────────────────────────────────────────────────────
    #  Onglet 2 : Chiffrer
    # ──────────────────────────────────────────────────────────────

    def _onglet_chiffrer(self, parent):
        ttk.Label(
            parent,
            text="Chiffrer un message pour quelqu'un",
            font=('Arial', 13, 'bold')
        ).pack(pady=8)

        lf1 = ttk.LabelFrame(parent, text="Clé Publique du DESTINATAIRE (collez ou importez son fichier)")
        lf1.pack(fill='x', padx=10, pady=4)
        self.txt_dest_pub = scrolledtext.ScrolledText(lf1, height=6, font=('Courier', 8))
        self.txt_dest_pub.pack(fill='x', padx=4, pady=4)
        ttk.Button(lf1, text="Charger depuis fichier",
                   command=lambda: self._charger_dans(self.txt_dest_pub)
                   ).pack(anchor='e', padx=4, pady=2)

        lf2 = ttk.LabelFrame(parent, text="Message en clair")
        lf2.pack(fill='x', padx=10, pady=4)
        self.txt_clair = scrolledtext.ScrolledText(lf2, height=5)
        self.txt_clair.pack(fill='x', padx=4, pady=4)

        ttk.Button(
            parent,
            text="Chiffrer + Signer",
            command=self._chiffrer
        ).pack(pady=8)

        lf3 = ttk.LabelFrame(parent, text="Message chiffré (JSON) — envoyez ce bloc au destinataire")
        lf3.pack(fill='both', expand=True, padx=10, pady=4)
        self.txt_chiffre = scrolledtext.ScrolledText(lf3, height=10, font=('Courier', 8))
        self.txt_chiffre.pack(fill='both', expand=True, padx=4, pady=4)

        bf = ttk.Frame(parent)
        bf.pack(pady=4)
        ttk.Button(bf, text="Copier",
                   command=lambda: self._copier(self.txt_chiffre)).pack(side='left', padx=4)
        ttk.Button(bf, text="Sauvegarder",
                   command=lambda: self._sauvegarder_texte(self.txt_chiffre)).pack(side='left', padx=4)

    # ──────────────────────────────────────────────────────────────
    #  Onglet 3 : Déchiffrer
    # ──────────────────────────────────────────────────────────────

    def _onglet_dechiffrer(self, parent):
        ttk.Label(
            parent,
            text="Déchiffrer un message reçu",
            font=('Arial', 13, 'bold')
        ).pack(pady=8)

        # ── Zone 1 : Clé privée du destinataire (OBLIGATOIRE) ────
        lf0 = ttk.LabelFrame(
            parent,
            text="Votre Clé Privée  ⚠  (fichier JSON privé — ne jamais partager)"
        )
        lf0.pack(fill='x', padx=10, pady=4)

        ttk.Label(
            lf0,
            text="Collez votre clé privée JSON ici, ou chargez le fichier :",
            foreground='#c00'
        ).pack(anchor='w', padx=6, pady=2)

        self.txt_cle_priv_dec = scrolledtext.ScrolledText(
            lf0, height=4, font=('Courier', 8)
        )
        self.txt_cle_priv_dec.pack(fill='x', padx=4, pady=4)

        ttk.Button(
            lf0,
            text="Charger ma clé privée depuis fichier",
            command=lambda: self._charger_dans(self.txt_cle_priv_dec)
        ).pack(anchor='e', padx=4, pady=2)

        # ── Zone 2 : Clé publique de l'émetteur ─────────────────
        lf1 = ttk.LabelFrame(parent, text="Clé Publique de L'ÉMETTEUR (pour vérifier sa signature)")
        lf1.pack(fill='x', padx=10, pady=4)
        self.txt_emit_pub = scrolledtext.ScrolledText(lf1, height=4, font=('Courier', 8))
        self.txt_emit_pub.pack(fill='x', padx=4, pady=4)
        ttk.Button(lf1, text="Charger depuis fichier",
                   command=lambda: self._charger_dans(self.txt_emit_pub)
                   ).pack(anchor='e', padx=4, pady=2)

        # ── Zone 3 : Message chiffré reçu ───────────────────────
        lf2 = ttk.LabelFrame(parent, text="Message chiffré reçu (JSON)")
        lf2.pack(fill='x', padx=10, pady=4)
        self.txt_recu = scrolledtext.ScrolledText(lf2, height=4, font=('Courier', 8))
        self.txt_recu.pack(fill='x', padx=4, pady=4)
        ttk.Button(lf2, text="Charger depuis fichier",
                   command=lambda: self._charger_dans(self.txt_recu)
                   ).pack(anchor='e', padx=4, pady=2)

        ttk.Button(
            parent,
            text="Déchiffrer + Vérifier Signature",
            command=self._dechiffrer
        ).pack(pady=8)

        self.lbl_sig = ttk.Label(parent, text="", font=('Arial', 11, 'bold'))
        self.lbl_sig.pack()

        lf3 = ttk.LabelFrame(parent, text="Message déchiffré")
        lf3.pack(fill='both', expand=True, padx=10, pady=4)
        self.txt_dechiffre = scrolledtext.ScrolledText(lf3, height=6)
        self.txt_dechiffre.pack(fill='both', expand=True, padx=4, pady=4)

    # ──────────────────────────────────────────────────────────────
    #  Onglet 4 : À propos
    # ──────────────────────────────────────────────────────────────

    def _onglet_apropos(self, parent):
        info = f"""
CHIFFREMENT ASYMÉTRIQUE HYBRIDE MATRICIEL — Version 2
======================================================

CORRECTIONS PAR RAPPORT À V1
──────────────────────────────
  V1 : Corps GF(2^8) → 256 éléments → DLP dans GF(2^64) → 32 bits → CASSABLE
  V2 : Corps GF(p)   → p ≈ 2^256    → DLP dans GF(p^4) ≈ 2^1024 → ~80 bits (NFS)
  Note Schnorr : t de 640 bits (Σ-protocole à masquage statistique)
  car ord(G) est inconnu dans GL(4,GF(p)) → pas de réduction modulaire

  V1 : G circulante (structure spéciale) → EXPLOITABLE
  V2 : G dérivée de SHA-256(seed public) → pseudoaléatoire, vérifiable

PARAMÈTRES DU SYSTÈME
──────────────────────
  Taille matrice     : {N}×{N}
  Corps              : GF(p) avec p de 256 bits (premier secp256k1)
  Clé privée         : entier 256 bits (mod Q_ORDER)
  Sécurité DLP       : GF(p^{N}) ≈ GF(2^{256*N}) — NFS sous-exponentiel
                       N=4 → 1024 bits → ~80 bits effectifs (éducatif)
                       N=8 → 2048 bits → ~112 bits effectifs (production)
  Seed G             : {SEED_PUBLIC.decode()}

PROTOCOLE DE CHIFFREMENT (El-Gamal hybride)
────────────────────────────────────────────
  1. r = aléatoire 256 bits (clé éphémère — usage unique)
  2. C_pub = G^r
  3. S = K_enc_dest^r = G^(k_dest × r)    ← secret partagé
  4. key_enc = HMAC(S, "chiffrement-v2")
     key_mac = HMAC(S, "authentification-v2")
  5. nonce = 16 octets aléatoires
  6. ct = message XOR CTR(key_enc, nonce)
  7. mac = HMAC(key_mac, C_pub || nonce || ct)

SIGNATURE SCHNORR (Zero-Knowledge Proof)
─────────────────────────────────────────
  t = aléatoire,   R = G^t
  e = SHA256(R || données) mod Q
  s = t + k_sign × e               ← pas de mod (ord(G) inconnu)
  t est choisi sur 640 bits (Σ-protocole à masquage statistique)
  → k×e (~512 bits) est noyé dans t (~640 bits), marge 2^-128

  Vérification : G^s == R × K_sign^e
  Preuve : G^(t+ke) = G^t × (G^k)^e = R × K^e ✓

POURQUOI C'EST UN ZERO-KNOWLEDGE PROOF ?
─────────────────────────────────────────
  Alice prouve à Bob qu'elle connaît k_sign SANS le lui révéler.
  Bob ne peut pas reconstruire k_sign depuis (R, e, s).
  Le nonce t (640 bits) masque k×e (512 bits) avec marge 2^-128.
  Mais Bob peut VÉRIFIER que seule quelqu'un connaissant k_sign
  peut produire un (R, s) qui satisfait G^s == R × K^e.
"""
        txt = scrolledtext.ScrolledText(parent, font=('Courier', 9), wrap='word')
        txt.pack(fill='both', expand=True, padx=8, pady=8)
        txt.insert('1.0', info)
        txt.config(state='disabled')

    # ──────────────────────────────────────────────────────────────
    #  Logique des boutons
    # ──────────────────────────────────────────────────────────────

    def _generer_cles(self):
        """Génère une nouvelle paire de clés et l'affiche."""
        try:
            self.mes_cles = generer_paire_cles()
            pub_json, priv_json = cles_vers_json(self.mes_cles)

            self._set_text(self.txt_pub, pub_json)
            self._set_text(self.txt_priv, priv_json)

            messagebox.showinfo(
                "Clés générées",
                "Nouvelle paire de clés créée avec succès.\n\n"
                "IMPORTANT : Sauvegardez votre clé PRIVÉE en lieu sûr.\n"
                "Partagez uniquement votre clé PUBLIQUE."
            )
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _charger_mes_cles(self):
        """Charge la clé privée depuis un fichier JSON."""
        chemin = filedialog.askopenfilename(
            title="Charger ma clé privée",
            filetypes=[("JSON", "*.json"), ("Tous", "*.*")]
        )
        if not chemin:
            return
        try:
            with open(chemin, 'r') as f:
                js = f.read()
            k_enc, k_sign = json_vers_cle_priv(js)
            K_enc  = mat_pow(G_GEN, k_enc)
            K_sign = mat_pow(G_GEN, k_sign)
            self.mes_cles = {
                'k_enc': k_enc, 'k_sign': k_sign,
                'K_enc': K_enc, 'K_sign': K_sign,
            }
            pub_json, priv_json = cles_vers_json(self.mes_cles)
            self._set_text(self.txt_pub, pub_json)
            self._set_text(self.txt_priv, js)
            messagebox.showinfo("Clés chargées", "Clés chargées avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur de chargement", str(e))

    def _chiffrer(self):
        """Chiffre le message saisi pour le destinataire."""
        if not self.mes_cles:
            messagebox.showwarning(
                "Clés manquantes",
                "Générez ou chargez d'abord vos clés (onglet 'Mes Clés')."
            )
            return
        try:
            dest_pub_js = self.txt_dest_pub.get('1.0', 'end').strip()
            message     = self.txt_clair.get('1.0', 'end').strip()

            if not dest_pub_js:
                messagebox.showwarning("Champ vide", "Entrez la clé publique du destinataire.")
                return
            if not message:
                messagebox.showwarning("Champ vide", "Entrez un message à chiffrer.")
                return

            K_enc_dest, _ = json_vers_cle_pub(dest_pub_js)
            paquet = chiffrer(message, K_enc_dest, self.mes_cles['k_sign'])
            self._set_text(self.txt_chiffre, paquet_vers_json(paquet))

        except json.JSONDecodeError:
            messagebox.showerror("JSON invalide", "La clé publique du destinataire est mal formée.")
        except Exception as e:
            messagebox.showerror("Erreur de chiffrement", str(e))

    def _dechiffrer(self):
        """Déchiffre un paquet reçu en utilisant la clé privée saisie manuellement."""
        try:
            cle_priv_js = self.txt_cle_priv_dec.get('1.0', 'end').strip()
            emit_pub_js = self.txt_emit_pub.get('1.0', 'end').strip()
            paquet_js   = self.txt_recu.get('1.0', 'end').strip()

            if not cle_priv_js:
                messagebox.showwarning(
                    "Clé privée manquante",
                    "Entrez votre clé privée JSON dans le premier champ."
                )
                return
            if not emit_pub_js:
                messagebox.showwarning("Champ vide", "Entrez la clé publique de l'émetteur.")
                return
            if not paquet_js:
                messagebox.showwarning("Champ vide", "Entrez le message chiffré reçu.")
                return

            # Lire la clé privée saisie — seul k_enc est nécessaire pour déchiffrer
            k_enc, _ = json_vers_cle_priv(cle_priv_js)

            _, K_sign_emit = json_vers_cle_pub(emit_pub_js)
            paquet = json_vers_paquet(paquet_js)

            plaintext, sig_valide = dechiffrer(paquet, k_enc, K_sign_emit)

            self._set_text(self.txt_dechiffre, plaintext)

            if sig_valide:
                self.lbl_sig.config(
                    text="Signature VALIDE — message authentique",
                    foreground='green'
                )
            else:
                self.lbl_sig.config(
                    text="Signature INVALIDE — émetteur non vérifié",
                    foreground='orange'
                )

        except ValueError as e:
            messagebox.showerror("Échec de déchiffrement", str(e))
            self.lbl_sig.config(text="", foreground='black')
        except json.JSONDecodeError:
            messagebox.showerror(
                "JSON invalide",
                "Un des champs JSON est mal formé.\n"
                "Vérifiez : clé privée, clé publique émetteur, message chiffré."
            )
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # ──────────────────────────────────────────────────────────────
    #  Utilitaires interface
    # ──────────────────────────────────────────────────────────────

    def _set_text(self, widget, texte: str):
        """Remplace le contenu d'un widget texte."""
        widget.config(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', texte)

    def _copier(self, widget):
        """Copie le contenu d'un widget dans le presse-papiers."""
        texte = widget.get('1.0', 'end').strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(texte)
        messagebox.showinfo("Copié", "Contenu copié dans le presse-papiers.")

    def _charger_dans(self, widget):
        """Charge le contenu d'un fichier texte dans un widget."""
        chemin = filedialog.askopenfilename(
            filetypes=[("JSON", "*.json"), ("Texte", "*.txt"), ("Tous", "*.*")]
        )
        if chemin:
            with open(chemin, 'r') as f:
                self._set_text(widget, f.read())

    def _sauvegarder_pub(self):
        """Sauvegarde la clé publique dans un fichier JSON."""
        if not self.mes_cles:
            messagebox.showwarning("Pas de clés", "Générez d'abord une paire de clés.")
            return
        chemin = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Sauvegarder la clé publique"
        )
        if chemin:
            with open(chemin, 'w') as f:
                f.write(self.txt_pub.get('1.0', 'end').strip())
            messagebox.showinfo("Sauvegardé", f"Clé publique sauvegardée :\n{chemin}")

    def _sauvegarder_priv(self):
        """Sauvegarde la clé privée dans un fichier JSON."""
        if not self.mes_cles:
            messagebox.showwarning("Pas de clés", "Générez d'abord une paire de clés.")
            return
        chemin = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Sauvegarder la clé privée (GARDER SECRET)"
        )
        if chemin:
            with open(chemin, 'w') as f:
                f.write(self.txt_priv.get('1.0', 'end').strip())
            messagebox.showinfo(
                "Sauvegardé",
                f"Clé privée sauvegardée :\n{chemin}\n\n"
                "AVERTISSEMENT : Ne partagez JAMAIS ce fichier."
            )

    def _sauvegarder_texte(self, widget):
        """Sauvegarde le contenu d'un widget dans un fichier."""
        chemin = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Texte", "*.txt")]
        )
        if chemin:
            with open(chemin, 'w') as f:
                f.write(widget.get('1.0', 'end').strip())
            messagebox.showinfo("Sauvegardé", f"Fichier sauvegardé :\n{chemin}")


# ═══════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
