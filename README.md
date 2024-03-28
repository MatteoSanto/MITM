# MITM
MITM con password sniffer
## Premessa
Questo codice è stato sviluppato per il solo scopo didattico e non vengono prese responsabilità per un eventuale uso inproprio.
## Funzionamento:
Il funzionamento si basa sul [Man-In-The-Middle](https://it.wikipedia.org/wiki/Attacco_man_in_the_middle) che viene effettuato tramite un attacco di tipo [ARP spoofer](https://it.wikipedia.org/wiki/ARP_poisoning) grazie al quale è possibile identificarsi su una rete con l'indirizzo [MAC](https://it.wikipedia.org/wiki/Indirizzo_MAC) di un altra macchina.
# Librerie
Per poter avviare il codice bisogna installare le seguenti librerie:
* scapy
* sys
* time
* os
* re
* urllib
Si possono installare col seguente comando:
```bash
pip install scapy, sys, time, os, re, urllib
```
## Avvio
Per avviare l'attacco bisogna aprire due terminali nella cartella in cui si trovano i due file.
Nel primo bisogna eseguire il seguente comando sostituendo i due indirizzi con quelli delle vittime:
```bash
python3 ARPspoofer.py indirizzoIP1 indirizzoIP2
```
# Codice
Di verranno seguito spiegati i codici dell'ARP spoofer e del Password sniffer.
## ARP spoofer
Import:
```python
import scapy.all as scapy
import sys, time, os
from scapy.layers.l2 import ARP, Ether
```
### Funzioni
