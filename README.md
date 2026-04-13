<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Crypto-From_Scratch-6366f1?style=for-the-badge" alt="From Scratch">
  <img src="https://img.shields.io/badge/GUI-Dark_Theme-0d1117?style=for-the-badge" alt="Dark Theme">
  <img src="https://img.shields.io/badge/Deps-Zero-22c55e?style=for-the-badge" alt="Zero deps">
</p>

# Chiffrement Asymetrique Hybride Matriciel

> Systeme de chiffrement asymetrique **construit entierement from scratch** en Python — sans aucune bibliotheque cryptographique externe. Projet educatif explorant le Probleme du Logarithme Discret (DLP) dans les groupes de matrices sur corps finis.

```
Cle privee  :  k         (entier secret, 256 bits)
Cle publique : K = G^k   (matrice 4x4 sur GF(p), partageable)

Securite : retrouver k depuis K = probleme du log discret dans GL(4, GF(p))
```

---

## Concept

Au lieu de s'appuyer sur RSA ou les courbes elliptiques, ce systeme fonde sa securite sur la **difficulte du logarithme discret dans GL(N, GF(p))** — le groupe des matrices inversibles N x N sur un corps premier de 256 bits.

Le DLP dans GL(4, GF(p)) se reduit au DLP dans GF(p^4) ~ GF(2^1024), offrant **~80 bits de securite classique** (attaque sous-exponentielle via NFS). Comparable a RSA-1024 — suffisant pour un projet educatif.

---

## Architecture

Le systeme combine trois briques, chacune implementee from scratch :

```
  Message                                              Paquet chiffre
     |                                                  + signe (JSON)
     v                                                       ^
 +------------------+    +---------------+    +------------------+
 | El-Gamal         | -> |   HMAC-CTR    | -> |     Schnorr      |
 | Matriciel        |    |               |    |     Matriciel    |
 | (echange de cle) |    | (chiffrement) |    |    (signature)   |
 +------------------+    +---------------+    +------------------+
   DH sur matrices       Symetrique rapide     Zero-knowledge proof
```

### El-Gamal hybride

Alice chiffre pour Bob :

1. **`r`** = aleatoire ephemere 256 bits (usage unique)
2. **`C_pub = G^r`** — partie publique envoyee a Bob
3. **`S = K_enc_Bob^r`** — secret partage (Diffie-Hellman matriciel)
4. Derive `key_enc` + `key_mac` via HMAC-SHA256 avec labels distincts
5. Chiffre en mode CTR, authentifie avec HMAC

Bob dechiffre : `S = C_pub^k_Bob = G^(r * k_Bob)` — meme secret, sans transmission directe.

### Schnorr matriciel

Preuve zero-knowledge que l'emetteur connait sa cle privee `k_sign` :

```
t = aleatoire (640 bits)       R = G^t
e = SHA256(R || donnees)       s = t + k_sign * e
```

**Verification** : `G^s == R * K_sign^e`

> Le nonce `t` est de **640 bits** (256 + 256 + 128 de marge) — technique standard des Sigma-protocoles pour masquer `k` statistiquement quand l'ordre du groupe est inconnu. Distance statistique <= 2^-128.

---

## Parametres

| Parametre | Valeur | Role |
|-----------|--------|------|
| `P_FIELD` | Premier 256 bits (secp256k1) | Corps de base GF(p) |
| `N` | 4 | Taille des matrices (4x4) |
| `BITS_CLE` | 256 | Cles privees |
| `BITS_NONCE_SIG` | 640 | Nonce de signature (Sigma-protocole) |
| `G_GEN` | SHA-256(seed public) | Generateur "nothing-up-my-sleeve" |

---

## Installation & lancement

### Prerequis

- **Python 3.8+**
- **tkinter** (inclus par defaut, ou `brew install python-tk@3.11` sur macOS Homebrew)
- Aucune dependance externe

### Lancement

```bash
python3 algo.py
```

L'application s'ouvre avec une interface dark theme et 3 onglets :

| Onglet | Fonction |
|--------|----------|
| **Mes Cles** | Generer ou charger une paire de cles (chiffrement + signature) |
| **Chiffrer** | Chiffrer et signer un message pour un destinataire |
| **Dechiffrer** | Dechiffrer et verifier la signature d'un message recu |

### Workflow

```
Alice                                     Bob
  |                                         |
  |  1. Genere ses cles                     |  1. Genere ses cles
  |  2. Envoie sa cle publique (.json) ---> |
  |  <--- Recoit la cle publique de Bob     |
  |                                         |
  |  3. Chiffre un message avec             |
  |     K_enc_Bob + signe avec k_sign_Alice |
  |                                         |
  |  4. Envoie le paquet JSON ------------> |
  |                                         |  5. Dechiffre avec k_enc_Bob
  |                                         |     Verifie avec K_sign_Alice
```

---

## Implemente from scratch

Tout le code cryptographique est ecrit a la main, sans appel a des bibliotheques externes :

- **Arithmetique GF(p)** — addition, multiplication, inverse (petit theoreme de Fermat)
- **Matrices sur GF(p)** — produit, inverse (Gauss-Jordan), exponentiation rapide (square-and-multiply)
- **Generateur G** — derive par hash chain SHA-256 depuis un seed public (nothing-up-my-sleeve)
- **KDF** — HMAC-SHA256 avec separation par labels
- **Chiffrement CTR** — flux pseudo-aleatoire HMAC-SHA256
- **MAC** — HMAC-SHA256 avec comparaison en temps constant
- **Signature Schnorr** — masquage statistique via Sigma-protocole (640 bits)
- **Serialisation** — JSON complet (cles, paquets chiffres)
- **Interface** — tkinter dark theme, zero dependance

---

## Structure du code

```
algo.py
  |
  |-- Partie 1 : Arithmetique GF(p)           gf_add, gf_mul, gf_inv
  |-- Partie 2 : Matrices sur GF(p)           mat_mul, mat_inv, mat_pow
  |-- Partie 3 : Generateur G_GEN             generer_G_depuis_seed
  |-- Partie 4 : Primitives symetriques       kdf, ctr_stream, xor_bytes
  |-- Partie 5 : Generation de cles           generer_paire_cles
  |-- Partie 6 : Chiffrement El-Gamal         chiffrer, dechiffrer
  |-- Partie 7 : Serialisation JSON           *_vers_json, json_vers_*
  |-- Partie 8 : Interface graphique          class App (dark theme)
```

---

## Limites

> **Projet strictement educatif — ne pas utiliser en production.**

| Limitation | Detail |
|------------|--------|
| Securite ~80 bits | Insuffisant par les standards modernes (minimum 128 bits) |
| Ordre de G inconnu | Empeche Schnorr classique — contourne via Sigma-protocole |
| Performance | Matrices en Python pur — generation de cles en quelques secondes |
| Pas de side-channel protection | Exponentiation matricielle non constante en temps |
| Pas de forward secrecy | Compromission de k_enc dechiffre tous les messages passes |

> Pour ~112 bits de securite : changer `N = 8` (matrices 8x8, DLP dans GF(p^8) ~ GF(2^2048)).
