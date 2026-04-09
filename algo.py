"""
Briques de base pour le chiffrement matriciel 8x8
Corps de Galois GF(2^8) + opérations matricielles
"""

import numpy as np
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ─────────────────────────────────────────────
#  PARAMÈTRE GLOBAL : taille de la matrice
# ─────────────────────────────────────────────
N = 8  # matrice 8×8 → blocs de 512 bits

# Polynôme irréductible pour GF(2^8)
# x^8 + x^4 + x^3 + x + 1 = 0x11b
# (différent de celui d'AES pour marquer notre indépendance)
# On utilise x^8 + x^5 + x^3 + x^2 + 1 = 0x12d
POLY = 0x12d


# ═══════════════════════════════════════════
#  PARTIE 1 : Arithmétique dans GF(2^8)
# ═══════════════════════════════════════════

def gf_add(a: int, b: int) -> int:
    """
    Addition dans GF(2^8).
    En binaire, additionner = XOR bit à bit.
    Exemple : 0b10110011 + 0b01001101 = 0b11111110
    """
    return a ^ b


def gf_mul(a: int, b: int) -> int:
    """
    Multiplication dans GF(2^8) par la méthode 'peasant russe'.
    On multiplie bit par bit en réduisant modulo POLY à chaque fois
    qu'on dépasse 8 bits.

    Idée : multiplier par 2 = décaler d'un bit à gauche.
           Si le résultat dépasse 8 bits → XOR avec le polynôme.
    """
    resultat = 0
    for _ in range(8):
        # Si le bit de poids faible de b est 1, on ajoute a au résultat
        if b & 1:
            resultat ^= a
        # Décaler a d'un bit vers la gauche (= multiplier par x)
        debordement = a & 0x80  # est-ce que le bit 7 est à 1 ?
        a = (a << 1) & 0xFF     # décalage + masque pour rester sur 8 bits
        if debordement:
            a ^= (POLY & 0xFF)  # réduction modulo le polynôme
        b >>= 1                 # on avance au bit suivant de b
    return resultat


def _construire_tables():
    """
    Précalcule les tables d'exponentiation et de logarithme dans GF(2^8).
    Ça accélère énormément la multiplication et l'inversion.

    L'idée : dans GF(2^8), l'élément g=0x02 est un générateur.
    Tout élément non nul peut s'écrire g^k pour un certain k.
    Donc a * b = g^(log(a) + log(b)).
    """
    exp_table = [0] * 512   # exp_table[k] = g^k
    log_table = [0] * 256   # log_table[a] = k tel que g^k = a

    val = 1
    for k in range(255):
        exp_table[k] = val
        log_table[val] = k
        val = gf_mul(val, 0x02)  # g = 0x02

    # Doubler la table pour éviter les modulos dans la multiplication
    for k in range(255, 512):
        exp_table[k] = exp_table[k - 255]

    return exp_table, log_table


EXP, LOG = _construire_tables()


def gf_mul_rapide(a: int, b: int) -> int:
    """
    Multiplication rapide via les tables log/exp.
    a * b = exp(log(a) + log(b))  si a,b ≠ 0
          = 0                      si a=0 ou b=0
    """
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def gf_inv(a: int) -> int:
    """
    Inverse multiplicatif dans GF(2^8).
    a * a^(-1) = 1
    Via les tables : a^(-1) = exp(255 - log(a))
    L'inverse de 0 n'existe pas → on retourne 0 par convention.
    """
    if a == 0:
        return 0
    return EXP[255 - LOG[a]]


def gf_pow(a: int, n: int) -> int:
    """
    Puissance dans GF(2^8) : a^n
    Via les tables : a^n = exp((log(a) * n) mod 255)
    """
    if a == 0:
        return 0
    if n == 0:
        return 1
    return EXP[(LOG[a] * n) % 255]


# ═══════════════════════════════════════════
#  PARTIE 2 : Opérations matricielles dans GF(2^8)
# ═══════════════════════════════════════════

def mat_add(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """
    Addition de matrices dans GF(2^8) = XOR composante par composante.
    """
    return np.bitwise_xor(A, B).astype(np.uint8)


def mat_mul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """
    Multiplication de matrices dans GF(2^8).
    Même formule que la multiplication classique,
    mais + = XOR et × = gf_mul_rapide.
    """
    n = A.shape[0]
    C = np.zeros((n, n), dtype=np.uint8)
    for i in range(n):
        for j in range(n):
            val = 0
            for k in range(n):
                val ^= gf_mul_rapide(int(A[i, k]), int(B[k, j]))
            C[i, j] = val
    return C


def mat_inv(M: np.ndarray) -> np.ndarray:
    """
    Inversion de matrice dans GF(2^8) par élimination de Gauss-Jordan.
    On transforme [M | I] → [I | M^(-1)]
    en utilisant l'arithmétique de GF(2^8).
    Lève une exception si la matrice n'est pas inversible.
    """
    n = M.shape[0]
    # Augmenter la matrice avec l'identité
    aug = np.zeros((n, 2 * n), dtype=np.uint8)
    aug[:, :n] = M.copy()
    for i in range(n):
        aug[i, n + i] = 1  # identité à droite

    for col in range(n):
        # Chercher un pivot non nul dans la colonne
        pivot = None
        for row in range(col, n):
            if aug[row, col] != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrice non inversible dans GF(2^8)")

        # Échanger les lignes
        aug[[col, pivot]] = aug[[pivot, col]]

        # Normaliser la ligne pivot (diviser par le pivot)
        inv_pivot = gf_inv(int(aug[col, col]))
        for j in range(2 * n):
            aug[col, j] = gf_mul_rapide(int(aug[col, j]), inv_pivot)

        # Éliminer la colonne dans toutes les autres lignes
        for row in range(n):
            if row != col and aug[row, col] != 0:
                facteur = int(aug[row, col])
                for j in range(2 * n):
                    aug[row, j] ^= gf_mul_rapide(facteur, int(aug[col, j]))

    return aug[:, n:].astype(np.uint8)


def mat_pow(M: np.ndarray, e: int) -> np.ndarray:
    """
    Exponentiation matricielle M^e par repeated squaring.
    M^0 = Identité
    M^e = M * M^(e-1) calculé efficacement en O(log e) multiplications.
    """
    n = M.shape[0]
    # Initialiser avec la matrice identité dans GF
    resultat = np.eye(n, dtype=np.uint8)
    base = M.copy()

    while e > 0:
        if e & 1:  # si le bit de poids faible est 1
            resultat = mat_mul(resultat, base)
        base = mat_mul(base, base)
        e >>= 1

    return resultat


# ═══════════════════════════════════════════
#  PARTIE 3 : Conversion texte ↔ matrices 8×8
# ═══════════════════════════════════════════

def texte_vers_matrices(message: str, n: int = N) -> list:
    """
    Convertit un texte en liste de matrices n×n d'octets.
    Padding PKCS#7 pour compléter le dernier bloc.
    """
    octets = message.encode('utf-8')
    taille_bloc = n * n  # 64 octets pour 8×8

    # Padding PKCS#7
    reste = len(octets) % taille_bloc
    nb_padding = taille_bloc - reste if reste != 0 else taille_bloc
    octets = octets + bytes([nb_padding] * nb_padding)

    # Découper et mettre en forme
    matrices = []
    for i in range(0, len(octets), taille_bloc):
        bloc = octets[i:i + taille_bloc]
        m = np.array(list(bloc), dtype=np.uint8).reshape(n, n)
        matrices.append(m)

    return matrices


def matrices_vers_texte(matrices: list) -> str:
    """
    Opération inverse : liste de matrices n×n → texte.
    Enlève le padding PKCS#7 automatiquement.
    """
    octets = bytes([int(val) for m in matrices for val in m.flatten()])

    # Enlever le padding
    nb_padding = octets[-1]
    if nb_padding > len(octets):
        raise ValueError("Padding invalide")
    octets = octets[:-nb_padding]

    return octets.decode('utf-8')


# ═══════════════════════════════════════════
#  PARTIE 4 : Tests et affichage
# ═══════════════════════════════════════════

def afficher_matrice(M: np.ndarray, titre: str = ""):
    """Affiche une matrice de façon lisible."""
    if titre:
        print(f"\n{'─' * 40}")
        print(f"  {titre}")
        print(f"{'─' * 40}")
    n = M.shape[0]
    for i in range(n):
        ligne = "  [ " + "  ".join(f"{int(v):3d}" for v in M[i]) + " ]"
        print(ligne)


class ChiffrementAsymetrique:
    def __init__(self, root):
        self.root = root
        self.root.title("Chiffrement Matriciel Asymétrique GF(2^8)")
        self.root.geometry("1200x800")
        
        self.cle_publique = None
        self.cle_privee = None
        self.message_original = ""
        self.message_chiffre = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Construit l'interface utilisateur"""
        # Menu principal avec onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Onglet 1 : Génération de clés
        frame_cles = ttk.Frame(notebook)
        notebook.add(frame_cles, text="🔑 Génération de Clés")
        self.setup_onglet_cles(frame_cles)
        
        # Onglet 2 : Chiffrement
        frame_chiffr = ttk.Frame(notebook)
        notebook.add(frame_chiffr, text="🔒 Chiffrement")
        self.setup_onglet_chiffrement(frame_chiffr)
        
        # Onglet 3 : Déchiffrement
        frame_dechiffr = ttk.Frame(notebook)
        notebook.add(frame_dechiffr, text="🔓 Déchiffrement")
        self.setup_onglet_dechiffrement(frame_dechiffr)
        
        # Onglet 4 : Visualisation
        frame_visu = ttk.Frame(notebook)
        notebook.add(frame_visu, text="📊 Visualisation")
        self.setup_onglet_visualisation(frame_visu)
    
    def setup_onglet_cles(self, frame):
        """Onglet de génération de clés asymétriques"""
        # Titre
        lbl_titre = ttk.Label(frame, text="Génération de Clés Publique/Privée", 
                             font=("Arial", 14, "bold"))
        lbl_titre.pack(pady=10)
        
        # Explication
        txt_explication = ttk.Label(frame, 
            text="Génère une paire de matrices inversibles dans GF(2^8).\n"
                 "Clé publique (A) : utilisée pour chiffrer\n"
                 "Clé privée (A⁻¹) : utilisée pour déchiffrer",
            justify="left")
        txt_explication.pack(pady=10)
        
        # Bouton de génération
        btn_generer = ttk.Button(frame, text="🔄 Générer une nouvelle paire de clés",
                                command=self.generer_cles)
        btn_generer.pack(pady=20)
        
        # Affichage des clés
        frame_cles_affich = ttk.LabelFrame(frame, text="Clé Publique (A)")
        frame_cles_affich.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.text_cle_pub = scrolledtext.ScrolledText(frame_cles_affich, height=12, 
                                                      width=80, font=("Courier", 9))
        self.text_cle_pub.pack(fill="both", expand=True)
        
        frame_cles_priv = ttk.LabelFrame(frame, text="Clé Privée (A⁻¹)")
        frame_cles_priv.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.text_cle_priv = scrolledtext.ScrolledText(frame_cles_priv, height=12, 
                                                       width=80, font=("Courier", 9))
        self.text_cle_priv.pack(fill="both", expand=True)
    
    def setup_onglet_chiffrement(self, frame):
        """Onglet de chiffrement"""
        lbl_titre = ttk.Label(frame, text="Chiffrement de Message", 
                             font=("Arial", 14, "bold"))
        lbl_titre.pack(pady=10)
        
        # Saisie du message
        lbl_msg = ttk.Label(frame, text="Message à chiffrer :")
        lbl_msg.pack(anchor="w", padx=10, pady=5)
        
        self.text_msg_original = scrolledtext.ScrolledText(frame, height=6, width=80)
        self.text_msg_original.pack(padx=10, pady=5, fill="both")
        
        # Bouton chiffrer
        btn_chiffrer = ttk.Button(frame, text="🔒 Chiffrer le message",
                                 command=self.chiffrer_message)
        btn_chiffrer.pack(pady=10)
        
        # Affichage du message chiffré
        lbl_chiffre = ttk.Label(frame, text="Message chiffré (hexadécimal) :")
        lbl_chiffre.pack(anchor="w", padx=10, pady=5)
        
        self.text_msg_chiffre = scrolledtext.ScrolledText(frame, height=12, width=80, 
                                                          font=("Courier", 8))
        self.text_msg_chiffre.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Bouton copier
        btn_copier = ttk.Button(frame, text="📋 Copier le message chiffré",
                               command=self.copier_chiffre)
        btn_copier.pack(pady=5)
    
    def setup_onglet_dechiffrement(self, frame):
        """Onglet de déchiffrement"""
        lbl_titre = ttk.Label(frame, text="Déchiffrement de Message", 
                             font=("Arial", 14, "bold"))
        lbl_titre.pack(pady=10)
        
        # Saisie du message chiffré
        lbl_chiffre = ttk.Label(frame, text="Message chiffré (hexadécimal) :")
        lbl_chiffre.pack(anchor="w", padx=10, pady=5)
        
        self.text_dechiff_input = scrolledtext.ScrolledText(frame, height=6, width=80,
                                                           font=("Courier", 8))
        self.text_dechiff_input.pack(padx=10, pady=5, fill="both")
        
        # Bouton déchiffrer
        btn_dechiffrer = ttk.Button(frame, text="🔓 Déchiffrer le message",
                                   command=self.dechiffrer_message)
        btn_dechiffrer.pack(pady=10)
        
        # Affichage du message déchiffré
        lbl_resultat = ttk.Label(frame, text="Message déchiffré :")
        lbl_resultat.pack(anchor="w", padx=10, pady=5)
        
        self.text_dechiff_output = scrolledtext.ScrolledText(frame, height=12, width=80)
        self.text_dechiff_output.pack(padx=10, pady=5, fill="both", expand=True)
    
    def setup_onglet_visualisation(self, frame):
        """Onglet de visualisation des matrices"""
        lbl_titre = ttk.Label(frame, text="Visualisation des Matrices", 
                             font=("Arial", 14, "bold"))
        lbl_titre.pack(pady=10)
        
        self.text_visualisation = scrolledtext.ScrolledText(frame, height=30, width=100,
                                                           font=("Courier", 8))
        self.text_visualisation.pack(padx=10, pady=10, fill="both", expand=True)
        
        btn_afficher = ttk.Button(frame, text="📊 Afficher les matrices",
                                 command=self.afficher_matrices)
        btn_afficher.pack(pady=10)
    
    def generer_cles(self):
        """Génère une paire de clés asymétriques"""
        try:
            # Générer une matrice 8×8 aléatoire inversible
            rng = np.random.default_rng()
            while True:
                self.cle_publique = rng.integers(1, 256, size=(8, 8), dtype=np.uint8)
                try:
                    self.cle_privee = mat_inv(self.cle_publique)
                    break
                except ValueError:
                    pass
            
            # Afficher les clés
            self.afficher_cles()
            messagebox.showinfo("Succès", "✓ Paire de clés générée avec succès !")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la génération : {e}")
    
    def afficher_cles(self):
        """Affiche les clés dans les zones de texte"""
        if self.cle_publique is None:
            return
        
        # Clé publique
        self.text_cle_pub.delete("1.0", "end")
        self.text_cle_pub.insert("1.0", "Clé Publique (Matrice A) :\n\n")
        for ligne in self.cle_publique:
            hex_ligne = " ".join(f"{v:02X}" for v in ligne)
            self.text_cle_pub.insert("end", hex_ligne + "\n")
        
        # Clé privée
        self.text_cle_priv.delete("1.0", "end")
        self.text_cle_priv.insert("1.0", "Clé Privée (Matrice A⁻¹) :\n\n")
        for ligne in self.cle_privee:
            hex_ligne = " ".join(f"{v:02X}" for v in ligne)
            self.text_cle_priv.insert("end", hex_ligne + "\n")
    
    def chiffrer_message(self):
        """Chiffre le message saisi"""
        if self.cle_publique is None:
            messagebox.showwarning("Attention", "Veuillez d'abord générer des clés !")
            return
        
        try:
            message = self.text_msg_original.get("1.0", "end-1c")
            if not message:
                messagebox.showwarning("Attention", "Veuillez entrer un message !")
                return
            
            self.message_original = message
            
            # Convertir en matrices
            matrices = texte_vers_matrices(message)
            
            # Chiffrer chaque matrice avec la clé publique
            matrices_chiffrees = []
            for m in matrices:
                m_chiffree = mat_mul(self.cle_publique, m)
                matrices_chiffrees.append(m_chiffree)
            
            self.message_chiffre = matrices_chiffrees
            
            # Afficher en hex
            self.text_msg_chiffre.delete("1.0", "end")
            for idx, m in enumerate(matrices_chiffrees, 1):
                hex_ligne = " ".join(f"{int(v):02X}" for v in m.flatten())
                self.text_msg_chiffre.insert("end", f"Bloc {idx}: {hex_ligne}\n")
            
            messagebox.showinfo("Succès", "✓ Message chiffré avec succès !")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement : {e}")
    
    def dechiffrer_message(self):
        """Déchiffre le message saisi"""
        if self.cle_privee is None:
            messagebox.showwarning("Attention", "Veuillez d'abord générer des clés !")
            return
        
        try:
            # Récupérer le texte chiffré et le parser
            texte_chiffre = self.text_dechiff_input.get("1.0", "end-1c")
            if not texte_chiffre:
                messagebox.showwarning("Attention", "Veuillez entrer un message chiffré !")
                return
            
            # Parser le hex
            hex_values = ''.join(texte_chiffre.split())
            octets = bytes.fromhex(hex_values)
            
            # Reconstruire les matrices (8×8 = 64 octets par bloc)
            matrices_chiffrees = []
            for i in range(0, len(octets), 64):
                bloc = octets[i:i+64]
                m = np.array(list(bloc), dtype=np.uint8).reshape(8, 8)
                matrices_chiffrees.append(m)
            
            # Déchiffrer avec la clé privée
            matrices_dechiffrees = []
            for m in matrices_chiffrees:
                m_dechiffree = mat_mul(self.cle_privee, m)
                matrices_dechiffrees.append(m_dechiffree)
            
            # Reconvertir en texte
            message_dechiffre = matrices_vers_texte(matrices_dechiffrees)
            
            self.text_dechiff_output.delete("1.0", "end")
            self.text_dechiff_output.insert("1.0", message_dechiffre)
            
            messagebox.showinfo("Succès", "✓ Message déchiffré avec succès !")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement : {e}")
    
    def afficher_matrices(self):
        """Affiche les matrices utilisées"""
        self.text_visualisation.delete("1.0", "end")
        
        if self.cle_publique is None:
            self.text_visualisation.insert("1.0", "Aucune clé générée.\n")
            return
        
        contenu = "═══════════════════════════════════════════\n"
        contenu += "CLÉ PUBLIQUE (Matrice A)\n"
        contenu += "═══════════════════════════════════════════\n\n"
        
        for i, ligne in enumerate(self.cle_publique):
            contenu += f"Ligne {i}: " + " ".join(f"{v:3d}" for v in ligne) + "\n"
        
        contenu += "\n═══════════════════════════════════════════\n"
        contenu += "CLÉ PRIVÉE (Matrice A⁻¹)\n"
        contenu += "═══════════════════════════════════════════\n\n"
        
        for i, ligne in enumerate(self.cle_privee):
            contenu += f"Ligne {i}: " + " ".join(f"{v:3d}" for v in ligne) + "\n"
        
        if self.message_chiffre:
            contenu += "\n═══════════════════════════════════════════\n"
            contenu += f"MESSAGE CHIFFRÉ ({len(self.message_chiffre)} bloc(s))\n"
            contenu += "═══════════════════════════════════════════\n\n"
            
            for idx, m in enumerate(self.message_chiffre, 1):
                contenu += f"Bloc {idx}:\n"
                for i, ligne in enumerate(m):
                    contenu += f"  " + " ".join(f"{v:3d}" for v in ligne) + "\n"
                contenu += "\n"
        
        self.text_visualisation.insert("1.0", contenu)
    
    def copier_chiffre(self):
        """Copie le message chiffré dans le presse-papiers"""
        texte = self.text_msg_chiffre.get("1.0", "end-1c")
        if texte:
            self.root.clipboard_clear()
            self.root.clipboard_append(texte)
            messagebox.showinfo("Succès", "✓ Message chiffré copié !")


if __name__ == "__main__":
    root = tk.Tk()
    app = ChiffrementAsymetrique(root)
    root.mainloop()

    print("=" * 50)
    print("  TEST 1 : Arithmétique GF(2^8)")
    print("=" * 50)

    a, b = 0x53, 0xCA
    print(f"\n  a = 0x{a:02X} ({a})")
    print(f"  b = 0x{b:02X} ({b})")
    print(f"\n  a + b (XOR)     = 0x{gf_add(a, b):02X}")
    print(f"  a * b (GF)      = 0x{gf_mul_rapide(a, b):02X}")
    print(f"  a^(-1)          = 0x{gf_inv(a):02X}")
    print(f"  a * a^(-1)      = 0x{gf_mul_rapide(a, gf_inv(a)):02X}  ← doit être 1")
    print(f"  a^3             = 0x{gf_pow(a, 3):02X}")

    print("\n" + "=" * 50)
    print("  TEST 2 : Multiplication et inversion matricielle")
    print("=" * 50)

    # Petite matrice 3×3 pour vérifier l'inversion
    # On génère une matrice inversible aléatoire
    rng = np.random.default_rng(42)
    while True:
        M_test = rng.integers(1, 256, size=(3, 3), dtype=np.uint8)
        try:
            mat_inv(M_test)
            break
        except ValueError:
            pass

    M_inv = mat_inv(M_test)
    produit = mat_mul(M_test, M_inv)

    afficher_matrice(M_test, "M (3×3 de test)")
    afficher_matrice(M_inv,  "M^(-1)")
    afficher_matrice(produit, "M × M^(-1)  ← doit être l'identité")

    print("\n" + "=" * 50)
    print("  TEST 3 : Exponentiation matricielle")
    print("=" * 50)

    M2 = np.array([
        [0x02, 0x01],
        [0x01, 0x03],
    ], dtype=np.uint8)

    afficher_matrice(M2,              "M (2×2)")
    afficher_matrice(mat_pow(M2, 2),  "M^2")
    afficher_matrice(mat_pow(M2, 0),  "M^0  ← doit être l'identité")

    print("\n" + "=" * 50)
    print("  TEST 4 : Conversion texte ↔ matrices 8×8")
    print("=" * 50)

    message = input("Votre message : ")
    matrices = texte_vers_matrices(message)

    print(f"\n  Message original  : {message!r}")
    print(f"  Longueur          : {len(message)} caractères")
    print(f"  Taille bloc 8×8   : 64 octets")
    print(f"  Nombre de blocs   : {len(matrices)}")

    afficher_matrice(matrices[0], "Matrice 1 (octets du message)")

    retour = matrices_vers_texte(matrices)
    print(f"\n  Message reconstitué : {retour!r}")
    print(f"  ✓ Identique : {message == retour}")

    # Afficher le message chiffré (hex) : représentation hexadécimale de tous les blocs
    cipher_hex = ''.join(f'{int(b):02X}' for m in matrices for b in m.flatten())
    print(f"\n  Message chiffré (hex compact) : {cipher_hex}")

    # Affichage lisible par bloc 8×8
    print("\n  Message chiffré (par bloc 8×8) :")
    for idx, m in enumerate(matrices, 1):
        flat = [int(x) for x in m.flatten()]
        row_hex = ' '.join(f'{v:02X}' for v in flat)
        print(f"  Bloc {idx:2d}: {row_hex}")
