# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | crackme05  |
| Hash SHA256 | ec2627be27552787f127ffb9ea5a6c2e3ffb58b3975e5bd2adfdb6f1343d05a7 |
| Format | ELF64 |
| Taille | 16064 octets |
| Compilateur | gcc |
| Packed | Non |

## 3. Analyse statique

### Graphe d'appels
`main()` → `printf` (prompt) → `fgets` → `strcspn` → `custom_hash(input)` → comparaison `h == 0xDEADBABE` → flag ou message d'échec affichant le hash calculé.

### Fonctions clés

#### custom_hash(const char *s)
```c
uint32_t h = 0x1337BEEF;
while (*s) {
    h = ((h << 5) | (h >> 27)) ^ (uint32_t)(*s);  
    h = h * 0x01000193u;                           
    s++;
}
return h;
```

#### main()
Compare le hash calculé à la constante cible `0xDEADBABE` codée en dur.


## 4. Analyse dynamique

### Trace d'exécution
```
gcc -o crackme05 crackme05_crypto.c -fno-stack-protector -no-pie

pip install z3-solver --break-system-packages

$ echo "wrong" | ./crackme05
[Crackme 05] Find preimage for hash 0xDEADBABE: [-] Hash: 0xDFDE3AE4 (need 0xDEADBABE) 

python3 solve.py

$ echo '.$kg' | ./crackme05
[Crackme 05] Find preimage for hash 0xDEADBABE: [+] Flag: CYBERSUP{z3_solv3d_th3_h4sh_deadbabe} 

```

## 5. Solution

### Reasoning
L'algorithme `custom_hash` étant composé d'opérations réversibles (rotation, XOR, multiplication par une constante impaire modulo 2³²): chaque caractère de l'entrée devient une variable 32 bits (bornée à l'intervalle ASCII imprimable 32–126), et la fonction de hash est reconstruite symboliquement tour par tour, avec pour contrainte finale `h == 0xDEADBABE`. Le solveur Z3 résout ce système et retourne une préimage valide. On itère sur la longueur jusqu'à obtenir une solution satisfiable.

### Script de solution
```python
# solve.py
import z3
import subprocess

TARGET = 0xDEADBABE
INIT = 0x1337BEEF
PRIME = 0x01000193

def solve_for_length(n, timeout_ms=30000):
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    chars = [z3.BitVec(f"c{i}", 32) for i in range(n)]
    for c in chars:
        s.add(c >= 32, c <= 126)   # ASCII imprimable

    h = z3.BitVecVal(INIT, 32)
    for c in chars:
        h = ((h << 5) | z3.LShR(h, 27)) ^ c
        h = h * PRIME
    s.add(h == TARGET)

    if s.check() == z3.sat:
        m = s.model()
        return "".join(chr(m[c].as_long()) for c in chars)
    return None

for n in range(1, 9):
    res = solve_for_length(n)
    if res:
        print(f"Preimage trouvee (longueur {n}) : {res!r}")
        r = subprocess.run(["./crackme05"], input=(res + "\n").encode(), capture_output=True)
        print(r.stdout.decode(errors="replace"))
        break
```

### Flag / Password
- Password (préimage trouvée par Z3) : `.$kg`
- Flag : `CYBERSUP{z3_solv3d_th3_h4sh_deadbabe}`
