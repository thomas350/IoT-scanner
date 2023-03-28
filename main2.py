# Avant utilisation, depuis un environnement Debian...
# Veillez à installer python3 sur la machine
# Veillez à installer nmap : apt-get install nmap ou npm install nmap
# Veillez à installer python-nmap sur la machine : pip3 install python-nmap (apt-get install pip ou pip3 si besoin)
# Veillez à installer colorama sur la machine : pip3 install colorama
# Veillez à installer hashcat : apt-get install hashcat
# doc utile :https://xael.org/pages/python-nmap-en.html#:~:text=python-nmap%20is%20a%20python,can%20even%20be%20used%20asynchronously

# Importation des librairies nécessaires
import os
import datetime
import nmap
from time import sleep
from colorama import Fore
import requests

# definition des variables globales
sc = nmap.PortScanner()
ports = '20,21,22,23,25,53,67,68,80,143,161,443,587,554,8000,9000,8888,6001'

""" 20: FTP data
21: FTP control port
22: SSH
23: Telnet (Insecure, not recommended for most uses)
25: SMTP
53: DNS services
67: DHCP server port
68: DHCP client port
80: HTTP - Unencrypted Web traffic
143: IMAP mail port
161: SNMP
443: HTTPS - Secure web traffic
587: SMTP - message submission port """

# définition des fonctions utilisées dans le programme
# Fonction principale (celle lancée au démarrage du script après les print pour afficher le )


def start():
    # ici on affiche les différents scanne que va faire le programme
    print("1-Discover active hosts on the network with OS infos\n2-Discover the ports and services on display\n3-Discover vulnerabilites\n4-Check for ExploitDB script\n5-Attempt brute force attack\n6-Default account ?\n7-Generate the audit report\n\n")
    # On stock le choix de l'utilisateur dans une variable
    choix_utilisateur = input("Enter your choice : ")

    # traitement du choix de l'utilisateur
    if choix_utilisateur == '1':
        nmap_ping_OS()
    if choix_utilisateur == '2':
        nmap_ports_and_service()
    if choix_utilisateur == '3':
        nmap_vuln()
    if choix_utilisateur == '4':
        exploit_db_script()
    if choix_utilisateur == '5':
        brute_force()
    if choix_utilisateur == '6':
        default_account()
    if choix_utilisateur == '7':
        generate_pdf()
    else:
        print("Please choose a number between 1 and 7")

# Fonction permettant de récupérer les informations sur l'OS de la machine


def nmap_ping_OS():
    print("-----Welcome to ping and OS scan-----\n")
    # ip = input("Please enter the network adress (addr/mask) : ")
    # sc.scan(hosts = ip, arguments="-n -sP")
    sc.scan(hosts='192.168.43.244',
            arguments=f' --script vulners.nse -p {ports} -sV -A -sS -O --osscan-guess -Pn')
    resultat = sc.all_hosts()[0]
    ip_address = resultat
    if 'mac' in sc[resultat]['addresses']:
        mac_address = sc[resultat]['addresses']['mac']
    else:
        mac_address = "None"
    name_of_device = sc[resultat]['hostnames'][0]['name']
    state = sc[resultat]['status']['state']

    osmatch = sc[resultat]['osmatch'][-1]
    type_of_device = osmatch['osclass'][0]['type']
    vendor = osmatch['osclass'][0]['vendor']
    os_family = osmatch['osclass'][0]['osfamily']
    name_of_product = osmatch['name']

    print(f"Name of device: {name_of_device}")
    print(f"IP Address: {ip_address}")
    print(f"MAC Address: {mac_address}")
    print(f"State: {state}")
    print(f"Type of device: {type_of_device}")
    print(f"Vendor: {vendor}")
    print(f"OS Family: {os_family}")
    print(f"Name of product: {name_of_product}")

    start()

# Fonction permettant de récupérer les ports et services ouverts avec leur version


def nmap_ports_and_service():
    print("-----Welcome to ports and service scan-----\n")
    ip = input("Please enter the network adress (addr/mask) : ")
    # on lance la commande nmap -sV -sS sur la range d'ip souaitée
    global ports
    sc.scan(hosts='192.168.44.249',
            arguments=f'--script vulners.nse -p {ports} -sV -Pn')
    print(sc)
    for host in sc.all_hosts():
        print(f'Host: {host}')
        for proto in sc[host].all_protocols():
            print(f'Protocol: {proto}')
            ports = sc[host][proto].keys()
            for port in ports:
                service = sc[host][proto][port]['name']
                product = sc[host][proto][port].get('product')
                version = sc[host][proto][port].get('version')
                extrainfo = sc[host][proto][port].get('extrainfo')
                print(f'Port: {port}, Service: {service}')
                if product:
                    print(f'Product: {product}')
                if version:
                    print(f'Version: {version}')
                if extrainfo:
                    print(f'Extra info: {extrainfo}')
    start()

# Fonction permettant de regarder les vulnérabilités d'une machine (CVE et defaut technique)


def nmap_vuln():
    print("-----Welcome to vulnscan check-----\n")
    # nmap --script vulscan/ -sV 192.168.43.244
    # nmap -sV --script vulners 192.168.43.244
    ip = input("Please enter the network adress (addr/mask) : ")
    print(os.system('nmap -sV --script=vulscan.nse '+ip))


# Fonction permettant de vérifier si il existe ou non un script dans exploitDB pouvant être utilisé pour attaquer la machine
def exploit_db_script():
    print("-----Welcome to exploitDB script check-----\n")
    url = "https://www.exploit-db.com/search"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    search_term = input('recherche : ')
    params = {'action': 'search', 'value': search_term}
    response = requests.get(url, headers=headers, params=params)
    print(response.text)


# Fonction permettant de récupérer faire un bruteforce avec hashcat
def brute_force():
    print("-----Welcome to brute force attempt-----\n")
    # on lance hashcat
    os.system('hashcat')

# Fonction permettant de vérifier la présence de compte usine


def default_account():
    print("-----Welcome to default account check-----\n")


# Fonction permettant de générer le rapport format PDF
def generate_pdf():
    print("-----Welcome to generate report-----\n")


# lancement du programme
if __name__ == "__main__":

    # Affichage du menu du programme. Il s'agit là uniquement de print avant le lancement de la premiere fonction.
    print(Fore.GREEN +
          '''
    ____    ______   _____                                 
   /  _/___/_  __/  / ___/_________ _____  ____  ___  _____
   / // __ \/ /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 _/ // /_/ / /     ___/ / /__/ /_/ / / / / / / /  __/ /
/___/\____/_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
''' + Fore.RESET)
sleep(1)
print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE + " Beginning of " +
      Fore.GREEN + "iot_scanner.py " + Fore.YELLOW + "v0" + Fore.RESET)
sleep(1)
print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE + " Starting script at ", Fore.YELLOW +
      datetime.datetime.now().strftime("%Y-%m-%d %H:%M" + Fore.WHITE + " GMT") + Fore.RESET)
sleep(1)
print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE +
      " Display of actions is loading ", Fore.WHITE + "..." + Fore.RESET)
sleep(1)
print("\nIoT Scanner menu :\n\n")

<<<<<<< HEAD
# lancement de la fonction principale
=======
#lancement de la fonction principale
>>>>>>> refs/remotes/origin/main
start()
