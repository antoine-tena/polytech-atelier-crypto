# Oral TP3 — Ce que j'ai compris

Liste de points à présenter (du général au concret).

## 1. Le but du TP
- Deux outils / deux angles : **netstat** pour *observer* l'état réseau de sa
  propre machine, et **nmap + Metasploit** (Kali) pour *attaquer* une machine
  cible volontairement vulnérable (Metasploitable2).
- La démarche d'un test d'intrusion : **reconnaissance → scan → énumération →
  exploitation → post-exploitation**.

## 2. netstat : lire l'état d'une machine
- `netstat -i` donne les **interfaces** et leurs flags (`U`=up, `R`=running,
  `L`=loopback, `B`=broadcast, `M`=multicast).
- `netstat -s` donne les **statistiques par protocole** (IP, ICMP, TCP, UDP).
- J'ai compris qu'une machine est un **routeur** si elle *relaie* des paquets
  (`Forwarding=1` **et** `forwarded > 0`), pas seulement si l'option est activée.
- Un **ping = ICMP Echo Request = type 8** : le nombre de pings émis se lit dans
  `OutType8`. Je l'ai **vérifié** : 5 pings → `OutType8: 5`.
- La **fragmentation IP** se mesure (`fragments created/reassembled`) ; avec le
  bit **DF (`-M do`)** un paquet trop grand n'est pas fragmenté mais provoque un
  ICMP « destination unreachable / frag needed ».
- Les **SYN cookies** protègent contre le **SYN flood** : le serveur n'alloue
  rien, il encode l'état dans le numéro de séquence du SYN-ACK.
- `netstat -tapn` : l'option **`-p`** révèle le **PID et le nom** du processus
  propriétaire d'une socket.

## 3. Le cycle de vie d'une socket TCP (le cœur du TP)
- TCP est **connecté** : ouverture par **3-way handshake** (SYN, SYN/ACK, ACK),
  fermeture par FIN/ACK. 11 états, dérivés des 6 flags `URG ACK PSH RST SYN FIN`.
- J'ai **observé en direct** avec netcat :
  - serveur `nc -l 5000` → **LISTEN** (ouverture passive) ;
  - client connecté → les **deux** bouts en **ESTABLISHED** ;
  - client fermé → l'extrémité qui ferme en premier passe en **TIME_WAIT**
    (~2×MSL, ≈60 s) pour laisser expirer les segments retardataires.
- Serveur **multiclient** = `nc -k -l 5000` : plusieurs `ESTABLISHED` coexistent
  avec le socket `LISTEN`.

## 4. TCP vs UDP (point clé)
- **UDP est sans connexion (stateless)** : pas de handshake, pas de FIN, la
  colonne `State` reste **vide**.
- Donc **pas de TIME_WAIT** en UDP : rien à fermer proprement, le socket
  disparaît immédiatement quand le client s'arrête. (Je l'ai vérifié.)
- Un client qui parle à un port UDP fermé reçoit un **ICMP port unreachable**.

## 5. Scan avec nmap (Kali → Metasploitable)
- Par défaut nmap scanne le **TCP** ; `-sU` pour l'**UDP**, `-sV` pour
  **service + version**.
- Le scan révèle les ports ouverts, les services et surtout leurs **versions** —
  c'est la version qui trahit la vulnérabilité (ici **vsftpd 2.3.4**, **PHP
  5.2.4**).

## 6. Énumération d'utilisateurs
- Deux méthodes : script NSE **`smb-enum-users`**, et **session nulle** Samba via
  **`rpcclient -U ""`** (connexion SMB **sans mot de passe**).
- Une session nulle fuite domaine + ~35 comptes **sans aucun accès admin** → d'où
  l'intérêt de la désactiver.

## 7. Exploitation vsftpd 2.3.4 — la backdoor « smiley »
- **Automatique** avec Metasploit : `use …/vsftpd_234_backdoor`, `set RHOSTS`,
  `exploit` → **shell root** (uid=0) via un **bind shell** sur le port **6200**.
- **Manuellement** : la backdoor se déclenche quand le login contient les octets
  **`0x3a` (`:`)** et **`0x29` (`)`)**, soit le smiley **`:)`**. La fonction
  cachée ouvre alors un shell root sur le port 6200, auquel on se connecte au
  **telnet**. J'ai compris *pourquoi* ça marche en lisant le code source.
- Vocabulaire Metasploit : **exploit** (déclenche la faille), **payload** (code
  exécuté ensuite), **bind shell** (on se connecte à la cible) vs **reverse
  shell** (la cible se connecte à nous, utile contre un pare-feu).

## 8. Service web : PHP CGI Argument Injection + meterpreter
- **PHP 5.2.4** → **CVE-2012-1823**, module `php_cgi_arg_injection` (rank
  excellent).
- Payload **`php/meterpreter/reverse_tcp`** : **reverse shell** vers l'attaquant
  (`LHOST`/`LPORT`). **meterpreter** = payload avancé en mémoire pour la
  post-exploitation (shell, upload, captures, etc.).
- **Defacing** : réécrire `index.php` dans `/var/www` pour montrer l'impact.

## 9. Ce que je retiens côté défense (contre-mesures)
- **Mettre à jour** les services (vsftpd, PHP, Samba) : presque toutes les failles
  venaient de versions anciennes et connues.
- **Durcir** : désactiver les sessions nulles SMB, fermer les ports inutiles,
  segmenter le réseau.
- **Isoler** une machine vulnérable (Metasploitable en NAT Network, jamais
  exposée) — même principe qu'un pot de miel / un labo.
- La même commande qui sert à l'attaque (nmap, netstat) sert à l'**audit
  défensif** : connaître ses ports ouverts et ses sockets, c'est se défendre.
