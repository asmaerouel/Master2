# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | crackme04  |
| Hash SHA256 | 3225572e4f89dccdee0982b616c061430f15fcf54a959f7f785171d8b969d4c8 |
| Format | ELF64 |
| Taille | 16184 octets |
| Compilateur | gcc |
| Packed | Non  |

## 3. Analyse statique

### Graphe d'appels
`main()` → boucle de décodage XOR sur `encrypted_func[]` (17 octets, en `.data`, adresse `0x404040`) → `printf` (prompt) → `fgets` → `strcspn` → `strcmp(input, (char*)encrypted_func)` → flag ou échec.

### Fonctions clés

#### main()
```c
static unsigned char encrypted_func[] = { 0xE9, 0xCE, ..., 0x00 };  // 17 octets, cle XOR = 0xAA
for (int i = 0; i < sizeof(encrypted_func); i++) encrypted_func[i] ^= 0xAA;
...
if (strcmp(input, (char *)encrypted_func) == 0) { ... flag ... }
```


## 4. Analyse dynamique


### Trace d'exécution
```
gcc -o crackme04 crackme04_packed.c -fno-stack-protector -no-pie

$ echo "wrong" | ./crackme04
[Crackme 04] Unpack and guess: [-] Decode the blob! 

objdump -s -j .data crackme04

python3 -c "
encrypted_func = [0xE9, 0xCE, 0xC9, 0xC9, 0xE1, 0xC4, 0xC6, 0xCE,
                   0xC7, 0xE1, 0xDA, 0xD1, 0xC4, 0xC9, 0xC9, 0xC8, 0x00]
secret = bytes([b ^ 0xAA for b in encrypted_func])
print(secret)"

cat > dump_secret.c << 'EOF'
#include <stdio.h>
#include <string.h>
static unsigned char encrypted_func[] = {
    0xE9, 0xCE, 0xC9, 0xC9, 0xE1, 0xC4, 0xC6, 0xCE, 0xC7, 0xE1, 0xDA, 0xD1, 0xC4, 0xC9, 0xC9, 0xC8, 0x00
};
int main(void) {
    for (int i = 0; i < (int)sizeof(encrypted_func); i++) encrypted_func[i] ^= 0xAA;
    printf("strlen = %zu\n", strlen((char*)encrypted_func));
    for (size_t i = 0; i < strlen((char*)encrypted_func) + 3; i++)
        printf("byte[%zu] = 0x%02x\n", i, encrypted_func[i]);
    return 0;
}
EOF

gcc -o dump_secret dump_secret.c -fno-stack-protector -no-pie
./dump_secret


python3 -c "
import subprocess
secret = bytes([0x43,0x64,0x63,0x63,0x4b,0x6e,0x6c,0x64,0x6d,0x4b,0x70,0x7b,0x6e,0x63,0x63,0x62,0xaa])
r = subprocess.run(['./crackme04'], input=secret + b'\n', capture_output=True)
print(r.stdout.decode(errors='replace'))"


```
## 5. Solution

### Reasoning
1. Extraire les 17 octets du tableau `encrypted_func` depuis la section `.data` (`objdump -s -j .data`, adresse `0x404040`).
2. Appliquer le XOR inverse  avec la clé `0xAA` sur chacun des 17 octets.
3. Constater que le dernier octet décodé est `0xAA` - la chaîne comparée par `strcmp` fait donc bien 17 octets.
4. Fournir ces 17 octets bruts  en entrée standard du programme.

### Flag / Password
- Password (bytes, 17 octets, contient l'octet non imprimable `0xAA` en fin de chaîne) : `CdccKnldmKp{nccb\xAA`
- Flag : `CYBERSUP{unp4ck3d_th3_s3cr3t}`
