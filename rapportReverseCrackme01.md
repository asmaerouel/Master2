# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | crackme01_c  |
| Hash SHA256 | 3284bfaaf2ef725c624151e1878742d3e3e6acec20d4f9722c6126d4e1a88308 |
| Format | ELF64 |
| Taille | 16128 octets |
| Compilateur | gcc |
| Packed | Non |


## 3. Analyse statique

### Graphe d'appels
`main()` appelle séquentiellement : `printf` → `fgets` → `strcspn` → `strcmp` → (`printf` du flag si succès, sinon `printf` "Wrong!").

### Fonctions clés

#### main()
Logique du source :
```c
const char *secret = "CyberSup_M2_Reverse_Rocks!";
char input[128];

printf("[Crackme 01] Password: ");
fgets(input, sizeof(input), stdin);
input[strcspn(input, "\n")] = 0;

if (strcmp(input, secret) == 0) {
    printf("[+] Flag: CYBERSUP{w3lc0m3_t0_r3v3rs3}\n");
    return 0;
}
printf("[-] Wrong!\n");
return 1;
```


#### sub_XXXX()
Aucune fonction auxiliaire : toute la logique est dans `main()`.

### Strings intéressantes
- `CyberSup_M2_Reverse_Rocks!` (mot de passe attendu)
- `[Crackme 01] Password: ` (prompt)
- `[+] Flag: CYBERSUP{w3lc0m3_t0_r3v3rs3}` (flag)
- `[-] Wrong!` (message d'échec)

## 4. Analyse dynamique

### Breakpoints posés
- `strcmp@plt` : permet d'observer directement les deux arguments comparés (input utilisateur vs secret).

### Trace d'exécution
```
$ echo "wrong" | ./crackme01_c
[Crackme 01] Password: [-] Wrong!       

$ echo "CyberSup_M2_Reverse_Rocks!" | ./crackme01_c
[Crackme 01] Password: [+] Flag: CYBERSUP{w3lc0m3_t0_r3v3rs3} 
```

## 5. Solution

### Reasoning

### Script de solution
```python
# solve.py
import subprocess

secret = "CyberSup_M2_Reverse_Rocks!"

result = subprocess.run(
    ["./crackme01_c"],
    input=secret + "\n",
    capture_output=True,
    text=True
)

print(result.stdout)
```

### Flag / Password
- Password : `CyberSup_M2_Reverse_Rocks!`
- Flag : `CYBERSUP{w3lc0m3_t0_r3v3rs3}`

