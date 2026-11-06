# TP3 INFO731 — NMAP, netstat & Kali (pentest)

Compte-rendu du TP3 « Sécurité et Cryptographie » (IDU4 — S7).

## Fichiers
- **`Compte-rendu TP3 - NMAP et Kali.docx`** — le **livrable** à déposer (Moodle).
- **`compte-rendu.md`** — la **source éditable** du compte-rendu (parties 1 et 2 +
  sorties réelles intégrées). Le docx en est généré via pandoc :
  ```bash
  pandoc compte-rendu.md -o "Compte-rendu TP3 - NMAP et Kali.docx" --standalone
  ```
- **`partie1_netstat/run.sh`** — script qui reproduit toutes les mesures netstat/netcat.
- **`partie1_netstat/sorties.txt`** — sorties réelles capturées (aussi en annexe du docx).
- **`ORAL.md`** — préparation d'oral (« ce que j'ai compris »), **hors** compte-rendu.

## Reproduire la partie 1
```bash
sudo apt-get install -y net-tools netcat-openbsd
cd partie1_netstat && bash run.sh
```

## État d'exécution
- Partie 1 (netstat/netcat) : **faite et vérifiée** sur une machine Linux.
- Partie 2 (VM Kali/Metasploitable) : guide complet prêt ; **à exécuter en TP**
  dans VirtualBox puis à illustrer par des captures d'écran pour le dépôt.
