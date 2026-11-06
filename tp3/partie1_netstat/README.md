# TP3 — Partie 1 : NMAP / netstat / netcat

Outil : `netstat` (net-tools) et `netcat` (`nc`). Toutes les sorties ci-dessous
sont **réelles**, capturées sur une machine Linux et reproductibles avec `./run.sh`
(voir aussi `sorties.txt`).

> Installation des outils : `sudo apt-get install -y net-tools netcat-openbsd`

---

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
- soit la pile locale refuse l'envoi : `ping: local error: message too long` ;
- soit un routeur intermédiaire renvoie un **ICMP type 3 code 4** (*fragmentation
  needed*), qui incrémente **`InType3`** (destination unreachable) côté ICMP.

→ La statistique affectée est donc **ICMP `InType3` / "destination unreachable
(frag needed)"** (et pas les compteurs de fragmentation, puisque DF les interdit).
À l'inverse, `ping -s 2000` **sans** DF incrémente lui `fragments created`.

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

---

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

**Si on arrête le serveur UDP :** le socket d'écoute `0.0.0.0:5000` disparaît lui
aussi instantanément. Un client qui continuerait d'émettre vers ce port recevrait
en retour un **ICMP type 3 code 3 (port unreachable)** — c'est d'ailleurs ce que
compte `packets to unknown port received` dans `netstat -s`.

---

## Rappel — les 11 états d'une socket TCP (sujet)
`CLOSED → LISTEN` (ouverture passive, serveur) ou `CLOSED → SYN_SENT` (ouverture
active, client) → `SYN_RECV` → `ESTABLISHED` → (fermeture) `FIN_WAIT1 →
FIN_WAIT2 → TIME_WAIT` côté actif, `CLOSE_WAIT → LAST_ACK` côté passif →
`CLOSED`. Ces états dérivent des **6 bits de flags** de l'en-tête TCP :
`URG, ACK, PSH, RST, SYN, FIN`.
