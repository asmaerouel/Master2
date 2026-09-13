# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | crackme02 |
| Hash SHA256 | 260c0300be560bacaf86457e363112d091e4f15340c07e96f5fcc80915d34bee |
| Format | ELF64 |
| Taille | 16216 octets |
| Compilateur | gcc |
| Packed | Non |


## 3. Analyse statique

### Graphe d'appels
`main()` → `printf` (prompt) → `fgets` → `strcspn` (retrait `\n`) → `check()` → (`printf` flag si succès, sinon `printf` "Nope.").
`check()` → `strlen` puis boucle de comparaison XOR octet par octet.

### Fonctions clés

#### main()
Logique du source : lit l'entrée , retire le retour à la ligne, appelle `check(input)`, affiche le flag si `check` renvoie 1.

#### check(const char *input)
```c
int len = sizeof(cipher);            // 15
if ((int)strlen(input) != len) return 0;
for (int i = 0; i < len; i++) {
    if ((input[i] ^ key[i % 3]) != cipher[i]) return 0;
}
return 1;
```

### Strings intéressantes
- `[Crackme 02] XOR secret: ` (prompt)
- `[+] Flag: CYBERSUP{x0r_1s_w34k_g0t_1t}` 
- `[-] Nope.` (message d'échec)
- `KEY` (clé XOR)
- Le tableau `cipher[]` n'apparaît pas dans les strings : il faut l'extraire depuis la section `.rodata`/`.data` via un désassembleur ou `objdump -s`.

## 4. Analyse dynamique


### Trace d'exécution
```
gcc -o crackme02 crackme02_xor.c -fno-stack-protector -no-pie

$ echo "wrong" | ./crackme02
[Crackme 02] XOR secret: [-] Nope.    

$ python3 -c "
import subprocess
cipher = [0x15,0x33,0x03,0x23,0x15,0x34,0x17,0x25,0x1C,0x26,0x0F,0x26,0x0F,0x37,0x14]
key = b'KEY'
plain = bytes([c ^ key[i%3] for i,c in enumerate(cipher)])
r = subprocess.run(['./crackme02'], input=plain+b'\n', capture_output=True)
print(r.stdout.decode(errors='replace'))
"
[Crackme 02] XOR secret: [+] Flag: CYBERSUP{x0r_1s_w34k_g0t_1t}  
```

### Observations
- Le password déchiffré contient un octet non imprimable (`0x7F`, DEL), ce qui empêche de le saisir directement au clavier / via `echo` en shell classique — il faut le fournir en binaire brut (via un script Python/pwntools qui pipe les bytes directement).


## 5. Solution

### Reasoning
Le commentaire d'en-tête indique un encodage XOR avec clé répétée. L'analyse statique du désassemblage de `check()` confirme : comparaison `input[i] ^ key[i % 3] == cipher[i]`. La clé `"KEY"` est lisible en clair dans les strings ; le tableau `cipher[]` (15 octets) est extrait depuis la section `.rodata`/`.data` du binaire (via `objdump -s` ou lecture directe dans Ghidra). Il suffit d'appliquer l'opération XOR inverse pour retrouver le password en clair, puis de le fournir en entrée.

### Script de solution
```python
# solve.py
import subprocess

cipher = [0x15, 0x33, 0x03, 0x23, 0x15, 0x34, 0x17, 0x25,
          0x1C, 0x26, 0x0F, 0x26, 0x0F, 0x37, 0x14]
key = b"KEY"

plain = bytes([c ^ key[i % 3] for i, c in enumerate(cipher)])
print("Password (bytes) :", plain)

result = subprocess.run(
    ["./crackme02"],
    input=plain + b"\n",
    capture_output=True
)
print(result.stdout.decode(errors="replace"))
```

### Flag / Password
- Password (bytes, contient un octet non imprimable `0x7F`) : `^vZhPm\`EmJ\x7fDrM`
- Flag : `CYBERSUP{x0r_1s_w34k_g0t_1t}`
