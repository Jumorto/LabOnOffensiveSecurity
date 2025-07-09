import os
import shlex
from scan import scan_hosts, scan_ifaces
from arp_spoofing import *
from dns_spoofing import start_dns_spoofing
import scapy.all as sc
from sslstripping_script import *
import time

def print_title():
    os.system('cls' if os.name == 'nt' else 'clear') # clears the console when starting

    def pause(text, delay=0.2):
        print (text)
        time.sleep(delay)

    print ("[:: GROUP 5 - DEFAULT PROJECT ::]\n")
    pause("> Initializing modules...", 0.3)
    pause("   + ARP Poisoning", 0.2)
    pause("   + DNS Spoofing", 0.2)
    pause("   + SSL Stripping", 0.2)
    pause("\n> Status: SYSTEMS ARMED", 0.2)
    pause("> Happy hunting! :)", 0.1)
    
def print_commands():

    commands = """
        Available Commands:
        scan_if       - Scan for available interfaces
        scan_hosts    - Scan for available hosts on a given interface
                        Params: -iface <interface>
        arppoison     - Start arp poison, with optional aggresive or silent modes
                        Params: -tgtip <target_ip> -spip <spoofed_ip> [-mode <mode>]
        dnsspoof      - Start dns spoof attack on a chosen target and domain 
                        Params: -iface <interface> -tgtip <target_ip> -dom <domain> -spaddr <spoofed_address>
        sslstrip      - Start SSL stripping attack
                        Params: -iface <interface> -tgtip <target_ip> -spip <spoofed_ip>
        help          - Show this help message
        exit          - Quit the tool
            """

    print(commands)


def handle_command(cmd):
    cmd = cmd.strip().lower()

    if cmd == "scan_if":
		# Scan available ifaces
        scan_ifaces()
    elif cmd.startswith("scan_hosts"):
		# Scan available hosts on given iface
        args = shlex.split(cmd)
        iface = None
        for i, arg in enumerate(args):
            if arg == "-iface" and i + 1 < len(args):
                iface = args[i + 1]
        scan_hosts(iface)
    elif cmd.startswith("arppoison"):
		# Basic arp poison
        start_arp_poison(cmd)
    elif cmd.startswith("dnsspoof"):
		# Basic dns spoofing
        start_dns_spoofing(cmd)
    elif cmd.startswith("sslstrip"):
        # Clear any process on port 8080 in order to start the SSL proxy
        stop_process8080()
        # Flush the content of iptables
        stop_iptables_redirect()
		# Start IP table
        start_iptables_redirect()
        # Start SSL stripping proxy
        start_sslstrip()
        # Start ARP poisoning for SSL stripping
        start_arp_poison_ssl(cmd)
    elif cmd == "help":
        print_commands()
    elif cmd == "exit":
        print("[*] Exiting...")
        exit(0)
    else:
        print("[!] Unknown command. Type 'help' to see available commands.")


def main():
    print_title()
    print_commands()
    while True:
        try:
            cmd = raw_input(">> ")
            handle_command(cmd)
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Type 'exit' to quit.")


if __name__ == '__main__':
    main()
