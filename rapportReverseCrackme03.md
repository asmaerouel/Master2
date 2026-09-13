# Rapport d'Analyse — Reverse Engineering

## 1. Identification du binaire

| Champ | Valeur |
|-------|--------|
| Nom fichier | crackme03  |
| Hash SHA256 | 51353419cc0cc4edfc537b566dcdfafad8de0db70c07be7c837cf2fd098b6a04 |
| Format | ELF64 |
| Taille | 16512 octets |
| Compilateur | gcc |
| Packed | Non |

## 3. Analyse statique

### Graphe d'appels
`main()` → `is_debugged_ptrace()` **ET** `is_debugged_status()` (évaluation avec court-circuit `||`) → si l'un des deux détecte un débogueur, message d'erreur + exit. Sinon → `printf` (prompt) → `fgets` → `strcspn` → `strcmp` → flag ou échec.


## 4. Analyse dynamique


### Contournement (bypass)
Hook `LD_PRELOAD` neutralisant `ptrace()` (retour systématique à 0) :
```c
// hook.c
#define _GNU_SOURCE
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, ...) {
    return 0;
}
```
```bash
gcc -shared -fPIC -o hook.so hook.c
LD_PRELOAD=./hook.so ./crackme03
```

### Trace d'exécution
```
gcc -o crackme03 crackme03_antidebug.c -fno-stack-protector -no-pie

cat > hook.c << 'EOF'
#define _GNU_SOURCE
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, ...) {
    return 0;
}
EOF

gcc -shared -fPIC -o hook.so hook.c

echo "antidebug_bypassed" | gdb -batch -ex run ./crackme03

echo "antidebug_bypassed" | LD_PRELOAD=./hook.so gdb -batch -ex run ./crackme03

```

## 5. Solution

### Reasoning
Le check anti-debug empêche toute exécution normale du binaire (même hors debug réel, comme démontré ci-dessus), donc il faut le neutraliser avant de pouvoir tester le mot de passe. La solution consiste à hooker `ptrace()` via `LD_PRELOAD` pour la forcer à toujours retourner 0 (comme si les deux appels `TRACEME`/`DETACH` réussissaient normalement), ce qui satisfait `is_debugged_ptrace()`. Le hook n'agit cependant pas sur `is_debugged_status()` par lui-même — mais puisque le hook empêche le `TRACEME` réel de s'exécuter , `TracerPid` reste à 0 dans `/proc/self/status`, donc `is_debugged_status()` passe également. Une fois les deux checks neutralisés, le mot de passe `antidebug_bypassed`  est fourni pour obtenir le flag.

### Script de solution
```bash
# hook.c : neutralise ptrace()
cat > hook.c << 'EOF'
#define _GNU_SOURCE
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, ...) {
    return 0;
}
EOF
gcc -shared -fPIC -o hook.so hook.c

# solve.sh
LD_PRELOAD=./hook.so bash -c 'echo "antidebug_bypassed" | ./crackme03'
```

### Flag / Password
- Password : `antidebug_bypassed`
- Flag : `CYBERSUP{ptr4c3_byp4ss3d_w1th_lr_pr3l0ad}`

## 6. IoC & YARA

## 7. Recommandations (si applicable)
