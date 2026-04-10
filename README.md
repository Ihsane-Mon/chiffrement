# 🔐 Chiffrement Matriciel Asymétrique — GF(2⁸)

Système de chiffrement asymétrique basé sur l'arithmétique matricielle dans le corps de Galois GF(2⁸), développé dans le cadre d'un projet universitaire de cryptographie.

> **Principe** : le message est découpé en blocs de 64 octets (matrices 8×8). Le chiffrement consiste à multiplier chaque matrice par une clé publique inversible dans GF(2⁸). Le déchiffrement utilise la matrice inverse (clé privée).

Pré-requis :
```
npm install
```
---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Aperçu](#-aperçu)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Architecture du code](#-architecture-du-code)
- [Fondements mathématiques](#-fondements-mathématiques)
- [Tests](#-tests)
- [Licence](#-licence)

---

## ✨ Fonctionnalités

- **Arithmétique complète dans GF(2⁸)** — addition (XOR), multiplication (paysan russe + tables log/exp), inversion, exponentiation
- **Opérations matricielles sur GF(2⁸)** — addition, multiplication, inversion (Gauss-Jordan), exponentiation rapide (repeated squaring)
- **Chiffrement / déchiffrement** — conversion texte ↔ matrices 8×8 avec padding PKCS#7
- **Interface graphique Tkinter** — génération de clés, chiffrement, déchiffrement et visualisation en 4 onglets
- **Batterie de tests intégrée** — vérification automatique de toutes les briques cryptographiques

---

## 🖼 Aperçu

L'application propose 4 onglets :

| Onglet | Description |
|--------|-------------|
| 🔑 Génération de Clés | Génère une matrice 8×8 aléatoire inversible (clé publique **A**) et son inverse (clé privée **A⁻¹**) |
| 🔒 Chiffrement | Saisie d'un message clair → chiffrement → affichage hexadécimal |
| 🔓 Déchiffrement | Saisie d'un message chiffré (hex) → déchiffrement → texte clair |
| 📊 Visualisation | Affichage détaillé des matrices de clés et des blocs chiffrés |

---

## 🛠 Prérequis

- **Python** 3.8+
- **NumPy** ≥ 1.20
- **Tkinter** (inclus dans la bibliothèque standard Python)

---

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/<votre-utilisateur>/chiffrement-matriciel-gf28.git
cd chiffrement-matriciel-gf28

# Installer les dépendances
pip install numpy
```

> **Note** : Tkinter est inclus par défaut avec Python. Sur certaines distributions Linux, installez-le séparément :
> ```bash
> sudo apt install python3-tk   # Debian / Ubuntu
> ```

---

## 💻 Utilisation

### Lancer l'interface graphique

```bash
python algo.py
```

### Workflow typique

1. **Générer les clés** — Onglet *Génération de Clés* → cliquer sur *Générer une nouvelle paire de clés*
2. **Chiffrer** — Onglet *Chiffrement* → saisir le message → cliquer sur *Chiffrer le message*
3. **Déchiffrer** — Onglet *Déchiffrement* → coller le message chiffré (hex) → cliquer sur *Déchiffrer le message*

### Tests console

Après la fermeture de l'interface graphique, 4 tests s'exécutent automatiquement dans le terminal (le test 4 demande une saisie utilisateur).

---

## 🏗 Architecture du code

```
algo.py
│
├── Partie 1 — Arithmétique GF(2⁸)
│   ├── gf_add(a, b)            # Addition (XOR)
│   ├── gf_mul(a, b)            # Multiplication (paysan russe)
│   ├── _construire_tables()    # Précalcul des tables EXP / LOG
│   ├── gf_mul_rapide(a, b)     # Multiplication O(1) via tables
│   ├── gf_inv(a)               # Inverse multiplicatif
│   └── gf_pow(a, n)            # Exponentiation
│
├── Partie 2 — Opérations matricielles
│   ├── mat_add(A, B)           # Addition matricielle (XOR)
│   ├── mat_mul(A, B)           # Multiplication matricielle
│   ├── mat_inv(M)              # Inversion (Gauss-Jordan)
│   └── mat_pow(M, e)           # Exponentiation rapide
│
├── Partie 3 — Conversion texte ↔ matrices
│   ├── texte_vers_matrices()   # Texte → liste de matrices 8×8
│   └── matrices_vers_texte()   # Matrices → texte (retrait PKCS#7)
│
├── Partie 4 — Interface & Tests
│   ├── afficher_matrice()      # Affichage console
│   └── ChiffrementAsymetrique  # Classe Tkinter (GUI complète)
│
└── __main__                    # Lancement GUI + tests console
```

---

## 🔢 Fondements mathématiques

### Corps de Galois GF(2⁸)

Chaque élément du corps est un octet (0x00 à 0xFF), interprété comme un polynôme de degré < 8 à coefficients binaires.

| Opération | Méthode | Détail |
|-----------|---------|--------|
| Addition | XOR | `a + b = a ⊕ b` |
| Multiplication | Paysan russe | Décalage + réduction modulo le polynôme irréductible |
| Polynôme irréductible | `0x12D` | x⁸ + x⁵ + x³ + x² + 1 |
| Générateur | `0x02` | Génère tous les éléments non nuls du corps |

### Optimisation par tables

Le générateur `g = 0x02` permet de précalculer :
- **EXP[k]** = g^k (512 entrées, doublée pour éviter les modulos)
- **LOG[a]** = k tel que g^k = a

Ainsi : `a × b = EXP[LOG[a] + LOG[b]]` en O(1).

### Schéma de chiffrement

```
Chiffrement :   C = A × M      (A = clé publique,  M = bloc clair)
Déchiffrement : M = A⁻¹ × C    (A⁻¹ = clé privée, C = bloc chiffré)
```

Le padding PKCS#7 assure que le message est toujours un multiple de 64 octets.

---

## 🧪 Tests

| # | Test | Vérification |
|---|------|-------------|
| 1 | Arithmétique GF(2⁸) | `a × a⁻¹ == 1` |
| 2 | Inversion matricielle 3×3 | `M × M⁻¹ == I` |
| 3 | Exponentiation matricielle | `M⁰ == I` |
| 4 | Conversion texte ↔ matrices | Message reconstitué == original |

Les tests s'exécutent automatiquement après la fermeture de l'interface graphique.

---

## ⚠️ Avertissement

Ce projet est réalisé à des fins **pédagogiques uniquement**. Ce système de chiffrement n'est pas conçu pour un usage en production et ne doit pas être utilisé pour protéger des données sensibles.

---

## 📄 Licence

Ce projet est distribué dans le cadre d'un projet universitaire.
