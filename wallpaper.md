# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | `wallpaper` |
| Hash SHA256 | `7526418ecada66780062b7f6ca7205c4540d6e2800fc994a4d02f75ae4b2b673` |
| Format | ELF64, x86-64, LSB, statiquement lié, stripped |
| Taille | 912 octets |
| Packed | Non |

## 2. Protections

| Protection | État |
|------------|------|
| NX | **Désactivé**  |
| PIE | **Non**  |
| Stack Canary | **N/A** |
| RELRO | **N/A**  |
| Fortify | **N/A** |

Binaire minimaliste artisanal : un seul header de programme, aucune section dynamique, syscalls Linux appelés directement (`read`, `write`, `exit`).

## 3. Analyse statique

### Graphe d'appels
N/A — pas de fonctions séparées, tout le code est linéaire dans un unique bloc `.text` avec sauts internes (pas de `call`/`ret` structurés hormis un trick `call`/`pop` pour récupérer une adresse absolue).

### Fonctions clés

#### Point d'entrée (0x400078)
```asm
; 1. Affiche "enter password"
mov rax, 1        ; sys_write
mov rdi, 1
lea rsi, [0x40024e]  ; "enter password\n"
mov rdx, 0xf
syscall

; 2. Lit jusqu'à 38 octets dans le buffer utilisateur
xor rax, rax      ; sys_read
xor rdi, rdi
lea rsi, [0x400297]  ; buffer d'entrée
mov rdx, 0x26
syscall
```

#### Bloc de validation "anti-junk" (0x4000ae – 0x4000dd)
Scanne le buffer de la fin (index 37) vers le début. Chaque octet doit appartenir à l'ensemble `{'\n', '0', '1', '2', '3'}` (test de bit via `bt` sur le masque `0xf000000000400`), sinon saut direct vers "wrong password". Conséquence : **le mot de passe ne peut être composé que des chiffres `0`-`3`** (et d'un `\n` éventuel en fin de buffer).

#### Boucle de vérification caractère par caractère (0x4000dd – 0x4001d4)
`rax` (64 bits = 16 nibbles) encode un **plateau de taquin (15-puzzle) 4×4** :
- État initial : `rax = 0xb6fd071e9c8a3425` → nibbles `[5,2,4,3,10,8,12,9,14,1,7,0,13,15,6,11]` (permutation valide de 0 à 15, `0` = case vide).
- Chaque caractère saisi (`'0'`–`'3'`) est normalisé en direction :
  - `0` → haut (−4 nibbles)
  - `1` → gauche (−1 nibble)
  - `2` → bas (+4 nibbles)
  - `3` → droite (+1 nibble)
- Un masque de 64 bits (`0x3bb97ffd7ffd6eec`) encode, pour chaque `(position, direction)`, si le mouvement est légal (équivalent aux règles de bord d'une grille 4×4 — vérifié : correspond exactement aux règles standards `row>0 / col>0 / row<3 / col<3`).
- Si le mouvement est illégal → saut vers "wrong password".
- Si légal → un enchaînement de `ror`/`or` sur la copie empilée de `rax` réalise l'échange (swap) entre la case vide et la case ciblée (mécanique classique du taquin).
- La boucle traite exactement **37 caractères** (index 0 à 36 ; le 38ᵉ octet du buffer n'est utilisé que par le scan anti-junk).

#### Vérification finale (0x4001d9)
```asm
xor rax, 0x123456789abcdef
xor rax, 0x1111111111111111
xor rax, 0xeeeeeeeeeeeeeeee
test rax, rax
jne wrong_password
```
Le plateau final attendu vaut `0x123456789abcdef ^ 0x1111111111111111 ^ 0xeeeeeeeeeeeeeeee = 0xfedcba9876543210`, soit les nibbles `[0,1,2,...,15]` dans l'ordre : **le taquin doit être résolu** (état trié standard).

### Strings intéressantes
- `enter password`
- `good job, validate with CMO{your_input}` — **template littéral**, pas de substitution dynamique : le flag = `CMO{` + mot de passe saisi + `}`
- `wrong password`

## 4. Analyse dynamique

### Breakpoints posés
- `*0x4001cb` (incrément de l'index de caractère `rdi`) → suivi de la progression (jusqu'où l'entrée passe la validation)
- `*0x400205` (branche "good job") → détection du succès
- `*0x400226` (branche "wrong password") → détection de l'échec

### Trace d'exécution
```
Entrée 'A'*38            → échec immédiat (bloc anti-junk, 'A' non autorisé)
Entrée '0'*38             → passe le bloc anti-junk, MAXRDI=1 (1er caractère seul validé)
Entrée finale (37 chiffres 0-3) → "good job, validate with CMO{your_input}"
```

### Observations
- Le bloc anti-junk initial est un piège contre le bruteforce naïf par octets ASCII quelconques : toute entrée "normale" (mot de passe alphanumérique classique + `\n`, reste du buffer à `0x00`) échoue instantanément car l'octet nul n'appartient pas au masque autorisé.
- Une première tentative de résolution par exécution symbolique (angr) n'a pas abouti dans un temps raisonnable (explosion d'états liée aux rotations dépendant de données symboliques).
- Une seconde tentative par recherche en profondeur (DFS + backtracking piloté par gdb) progressait mais restait coûteuse (~50ms par tentative, milliers d'essais nécessaires).
- La reconstruction manuelle de la sémantique de la boucle (recherche du nibble à zéro + swap conditionné par bitmask) a permis d'identifier le modèle exact (15-puzzle), rendant la résolution triviale par un solveur dédié.

## 5. Solution

### Reasoning
1. Repérage du bloc anti-junk → restreint l'alphabet du mot de passe à `{0,1,2,3}`.
2. Reverse manuel de la boucle de transformation par caractère → identification d'un swap de nibbles dans `rax` conditionné par une bitmask de règles de bord.
3. Vérification empirique : le masque de légalité (`0x3bb97ffd7ffd6eec`) correspond exactement aux règles de bord d'une grille 4×4 (`row>0`, `col>0`, `row<3`, `col<3`) → confirmation qu'il s'agit d'un taquin (15-puzzle).
4. État initial et état cible (calculé via les 3 XOR finaux) décodés en plateaux 4×4 → tous deux des permutations valides de `0`–`15`, l'état cible étant l'état trié standard.
5. Résolution par **IDA\*** (heuristique de distance de Manhattan) → solution optimale de longueur **37**, correspondant exactement à la longueur imposée par le buffer (aucun padding nécessaire).

### Script de solution
```python
# solve_puzzle.py — extrait
init_nib = [5, 2, 4, 3, 10, 8, 12, 9, 14, 1, 7, 0, 13, 15, 6, 11]
goal_nib = list(range(16))
DELTAS = {0: -4, 1: -1, 2: 4, 3: 1}   # haut, gauche, bas, droite

def valid_move(pos, d):
    row, col = divmod(pos, 4)
    if d == 0: return row > 0
    if d == 1: return col > 0
    if d == 2: return row < 3
    if d == 3: return col < 3

# IDA* avec heuristique de Manhattan (voir script complet en annexe)
# → moves = [1,0,0,1,2,2,3,2,1,0,1,2,3,0,1,0,3,0,1,2,3,3,3,2,2,1,1,0,1,0,3,3,2,1,0,0,1]
```

Vérification :
```bash
echo -n "1001223210123010301233322110103321001" | ./wallpaper
# => good job, validate with CMO{your_input}
```

### Flag / Password
- **Mot de passe** : `1001223210123010301233322110103321001`
- **Flag** : `CMO{1001223210123010301233322110103321001}`

```

