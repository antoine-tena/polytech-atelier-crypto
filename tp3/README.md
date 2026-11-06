# TP3 INFO731 — NMAP, netstat & Kali (pentest)

Compte-rendu du TP3 « Sécurité et Cryptographie » (IDU4 — S7).

> **Livrable à déposer :** `Compte-rendu TP3 - NMAP et Kali.docx` (généré depuis
> `README.md` + `partie1_netstat/README.md` + `partie2_kali/README.md` via pandoc,
> sorties réelles intégrées). Les `.md` restent la source éditable ; `ORAL.md` est
> la préparation d'oral (hors compte-rendu).

## Contenu
- **`partie1_netstat/`** — netstat + netcat (états des sockets TCP/UDP).
  Questions 1 à 14 **exécutées réellement** sur Linux :
  - `README.md` : réponses détaillées Q1–Q14 ;
  - `run.sh` : script qui reproduit toutes les mesures ;
  - `sorties.txt` : sorties réelles capturées.
- **`partie2_kali/`** — Kali Linux vs Metasploitable2 dans VirtualBox :
  config réseau, scan nmap (TCP/UDP/`-sV`), énumération d'utilisateurs
  (`smb-enum-users`, `rpcclient` session nulle), exploitation **vsftpd 2.3.4**
  (auto via Metasploit + manuelle via le smiley `:)`), **PHP CGI Argument
  Injection** + reverse shell meterpreter, defacing.
  → à **exécuter sur les deux VM**, les commandes et sorties attendues servent de
  guide/compte-rendu.
- **`ORAL.md`** — points à présenter à l'oral (ce que j'ai compris du TP3).

## Reproduire la partie 1
```bash
sudo apt-get install -y net-tools netcat-openbsd
cd partie1_netstat && bash run.sh
```

## État d'exécution
- Partie 1 (netstat/netcat) : **faite et vérifiée** sur cette machine Linux.
- Partie 2 (VM Kali/Metasploitable) : guide complet prêt ; **à exécuter en TP**
  dans VirtualBox (impossible hors des VM) puis capturer les écrans pour le dépôt.
