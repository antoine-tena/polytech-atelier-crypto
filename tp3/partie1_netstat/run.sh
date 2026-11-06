#!/usr/bin/env bash
# TP3 INFO731 - Partie 1 : netstat + netcat (états des sockets)
# Reproduit toutes les mesures de la partie NMAP/netstat du sujet.
# Prérequis : net-tools (netstat) et netcat-openbsd (nc).
#   sudo apt-get install -y net-tools netcat-openbsd
set -u

sep(){ echo; echo "=================== $* ==================="; }

sep "Q1 - Statistiques sur les interfaces (netstat -i)"
netstat -i

sep "Routeur ? (Q2) - Forwarding IP"
echo "netstat -s | grep Forwarding :"
netstat -s | grep -i forwarding
echo "cat /proc/sys/net/ipv4/ip_forward :"
cat /proc/sys/net/ipv4/ip_forward

sep "Q3 - Nombre de ping emis = ICMP OutType8 (echo request)"
echo "--- avant ---"; netstat -s | grep -E "OutType8" || echo "OutType8: 0 (aucun echo encore emis)"
ping -c 3 127.0.0.1 >/dev/null 2>&1
echo "--- apres 3 pings ---"; netstat -s | grep -E "OutType8"

sep "Q4/Q5 - Fragmentation IP"
echo "ping -s 2000 (taille > MTU 1500 sur eth0 -> fragmentation) :"
ping -c 1 -s 2000 127.0.0.1 2>&1 | head -2
echo "Q5 : ping -s 1500 -M do (bit DF, interdit la fragmentation) :"
ping -c 1 -s 1500 -M 'do' 127.0.0.1 2>&1 | head -2
echo "Compteurs fragmentation :"
netstat -s | grep -Ei "fragments|reassemb" || echo "(aucun sur loopback : MTU 65536)"

sep "Q7 - Nom + PID des processus proprietaires des sockets TCP"
echo "Option -p (--program) ; ex : netstat -tapn  (t=tcp a=all p=pid n=numerique)"

sep "Q9 - Serveur TCP port 5000 -> etat LISTEN"
nc -l 5000 >/dev/null 2>&1 & S=$!; sleep 1
netstat -nta | grep -E ":5000|Proto"

sep "Q10/Q11 - Client TCP connecte -> ESTABLISHED (netstat -nta | grep ':5000|Address')"
nc 127.0.0.1 5000 >/dev/null 2>&1 & C=$!; sleep 1
netstat -nta | grep -E ":5000|Proto"

sep "Q11b - Fin du client -> TIME_WAIT du cote qui ferme activement"
kill "$C" 2>/dev/null; sleep 1
netstat -nta | grep -E ":5000|Proto"
kill "$S" 2>/dev/null; wait 2>/dev/null

sep "Q12 - Serveur TCP multiclient (-k) + serveur UDP multiclient (-u -k)"
echo "Commandes exactes :"
echo "  TCP multiclient : nc -k -l 5000"
echo "  UDP multiclient : nc -u -k -l 5000"
nc -k -l 5000 >/dev/null 2>&1 & ST=$!
nc -u -k -l 5000 >/dev/null 2>&1 & SU=$!
sleep 1

sep "Q13 - Etats TCP et UDP sur 5000, puis plusieurs clients"
nc 127.0.0.1 5000 >/dev/null 2>&1 & C1=$!
nc 127.0.0.1 5000 >/dev/null 2>&1 & C2=$!
(echo bonjour; sleep 3) | nc -u 127.0.0.1 5000 >/dev/null 2>&1 & CU=$!
sleep 1
echo "--- TCP ---"; netstat -nta | grep -E ":5000|Proto"
echo "--- UDP ---"; netstat -nua | grep -E ":5000|Proto"

sep "Q14 - Fin du client UDP -> pas de TIME_WAIT (UDP sans etat)"
kill "$CU" 2>/dev/null; sleep 1
netstat -nua | grep -E ":5000|Proto"

kill "$C1" "$C2" "$ST" "$SU" 2>/dev/null; wait 2>/dev/null
echo; echo "=== FIN ==="
