from scapy.all import arping, get_if_addr, get_if_hwaddr, get_if_list

active_hosts = []
# Scan for available network interfaces
def scan_ifaces():
    interfaces = get_if_list()
    print("\033[93m[*] Available network interfaces: \033[0m")
    for iface in interfaces:
        print(" - {}".format(iface))
        
# Scan for active hosts on a given interface
def scan_hosts(iface):
    del active_hosts[:]
    print("\033[93m[*] Host scanning initiated...\033[0m")
    
    iface = iface
    if not iface:
        print("\033[31m[!] Cannot proceed without a valid network interface.\033[0m")
        return

    host_ip = get_if_addr(iface)
    host_mac = get_if_hwaddr(iface)

    subnet = ".".join(host_ip.split(".")[:3]) + ".0/24"
    print("\033[93m[*] Scanning subnet " + subnet + " on interface:\033[0m" + iface)

    try:
        ans, _ = arping(subnet, iface=iface, verbose=False, timeout=2)
        for sent, recv in ans:
            ip = recv.psrc
            mac = recv.hwsrc
            active_hosts.append({"ip_addr": ip, "mac_addr": mac})
        print("\033[92m[+] Scan complete. Active hosts found:\033[0m" + str(len(active_hosts)))

        for host in active_hosts:
            print("IP: " + str(host['ip_addr']) + "| MAC: " + str(host['mac_addr']))
    except Exception as e:
        print("\033[31m[!] ARP scan failed: \033[0m" + str(e))
