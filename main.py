import os
import datetime
from time import sleep
from colorama import init, Fore

init()

print(Fore.GREEN +   
'''
    ____    ______   _____                                 
   /  _/___/_  __/  / ___/_________ _____  ____  ___  _____
   / // __ \/ /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 _/ // /_/ / /     ___/ / /__/ /_/ / / / / / / /  __/ /
/___/\____/_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
''' + Fore.RESET);sleep(1)

print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE +" Beginning of " + Fore.GREEN + "iot_scanner.py " + Fore.YELLOW + "v0" + Fore.RESET),sleep(1)
print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE +" Starting script at ", Fore.YELLOW + datetime.datetime.now().strftime("%Y-%m-%d %H:%M" + Fore.WHITE + " GMT") + Fore.RESET);sleep(1)
print("[" + Fore.YELLOW + "*" + Fore.WHITE + "]" + Fore.BLUE +" Display of actions is loading ", Fore.WHITE + "..." + Fore.RESET);sleep(1)

while True:
    print('''
        IoT Scanner menu :
            1) Discover active hosts on the network
            2) Discover the ports and services on display
            3) Discover the operating systems on the network
            4) Discover vulnerabilites
            5) Generate the audit report
    ''')
    
    choice = input("Enter your choice: ")
    
    if choice == '1':
        os.system('nmap -sn <IP range>')
    elif choice == '2':
        os.system('nmap -sV <IP range>')
    elif choice == '3':
        os.system('nmap -O <IP range>')
    elif choice == '4':
        os.system('nmap --script vuln <IP range>')
    elif choice == '5':
        # Code to generate audit report here
        pass