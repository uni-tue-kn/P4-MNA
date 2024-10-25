#################################################################
# MPLS Network Actions Framework Library                        #
# Created by Fabian Ihle, 25.04.2024                            #
# github: https://github.com/uni-tue-kn/P4-MNA                  #
#                                                               #
# Description:                                                  #
# This scripts contains examples on how to use the MNA library  #
# ------------------------------------------------------------- #
# Changelog:                                                    #
# 25.04.2024 - Initial version                                  #
# 25.10.2024 - Bug fixes introduced with latest encoding        #
#################################################################

from scapy.all import Ether, IP, get_if_hwaddr, sendp, Raw, UDP
from MNA import NAS, MPLS_LSE, Scope, UnkownActionHandling, PSDTopHeader

def label_stack_hbh_select(hbh_count=2, select_count=2):
    # Forwarding Label 1
    l1 = MPLS_LSE(label=50, tc=7, bos=0, ttl=63)
    # Forwarding Label 2
    l2 = MPLS_LSE(label=60, tc=7, bos=0, ttl=63)
    # Forwarding Label 3
    l3 = MPLS_LSE(label=70, tc=7, bos=0, ttl=63)

    # Create a new NAS with a bSPL and an initial opcode LSE
    hbh_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.HBH,unknown_action_handling=UnkownActionHandling.IGNORE)
    for _ in range(hbh_count):
        # Add subsequent opcodes
        hbh_nas.add_subsequent_opcode(opcode=64, data=2, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)
    select_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.SELECT, unknown_action_handling=UnkownActionHandling.IGNORE)
    for _ in range(select_count):
        select_nas.add_subsequent_opcode(opcode=64, data=2, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)

    # Add ancillary data to first subsequent opcode
    hbh_nas.subsequent_opcodes[0].add_ancillary_data(0, 0)

    # Different combinations of label stacks
    #label_stack = [l1, select_nas, hbh_nas, l2]
    #label_stack = [l1, l3, hbh_nas, select_nas, l2]
    #label_stack = [l1, l3, hbh_nas, l2]
    #label_stack = [l1, l3, select_nas, l2]
    #label_stack = [l1, select_nas, l3, hbh_nas, l2]
    label_stack = [l1, select_nas, l3, select_nas, hbh_nas, l2]
    return label_stack

def label_stack_hbh_only(number_of_actions=2):
    """
    This function generates an MPLS stack with a forwarding label, an HBH NAS, and another forwarding label
    """
    try:
        assert number_of_actions <= 16
    except AssertionError:
        print("A NAS can at most have 16 network actions!")
        return []

    hbh_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.HBH,unknown_action_handling=UnkownActionHandling.IGNORE)
    l1 = MPLS_LSE(label=50, tc=7, bos=0, ttl=63)
    # Forwarding Label 2
    l2 = MPLS_LSE(label=60, tc=7, bos=0, ttl=63)

    for _ in range(number_of_actions - 1):
        hbh_nas.add_subsequent_opcode(opcode=64, data=0, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)

    # Ancillary Data can be added like this
    #hbh_nas.subsequent_opcodes[0].add_ancillary_data(0, 0)

    label_stack = [l1, hbh_nas, l2]
    return label_stack

def label_stack_ioam_path_tracing():
    """
    This function generates an MPLS stack with multiple forwarding labels.
    It is intended to be used with the HBH NAS Preservation concept.
    """
    # Forwarding Label 1
    l1 = MPLS_LSE(label=500, tc=7, bos=0, ttl=63)
    # Forwarding Label 2
    l2 = MPLS_LSE(label=600, tc=7, bos=0, ttl=63)
    # Forwarding Label 3
    l3 = MPLS_LSE(label=700, tc=7, bos=0, ttl=63)
    l4 = MPLS_LSE(label=800, tc=7, bos=0, ttl=63)
    l5 = MPLS_LSE(label=900, tc=7, bos=0, ttl=63)
    l6 = MPLS_LSE(label=1000, tc=7, bos=0, ttl=63)
    hbh_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.HBH, unknown_action_handling=UnkownActionHandling.IGNORE)

    hbh_nas.add_subsequent_opcode(opcode=42, data=16, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)
    for i in range(5):
        hbh_nas.subsequent_opcodes[0].add_ancillary_data(0, 0)

    label_stack = [l1, hbh_nas, l2, l3, l4, l5, l6]
    return label_stack


def label_stack_select_only(number_of_actions=2):
    """
    This function generates an MPLS stack with a forwarding label, a Select NAS, and another forwarding label
    """    
    try:
        assert number_of_actions <= 16
    except AssertionError:
        print("A NAS can at most have 16 network actions!")
        return []
        
    hbh_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.SELECT, unknown_action_handling=UnkownActionHandling.IGNORE)
    l1 = MPLS_LSE(label=50, tc=7, bos=0, ttl=63)
    # Forwarding Label 2
    l2 = MPLS_LSE(label=60, tc=7, bos=0, ttl=63)

    for _ in range(number_of_actions - 1):
        hbh_nas.add_subsequent_opcode(opcode=64, data=0, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)

    label_stack = [l1, hbh_nas, l2]
    return label_stack

def label_stack_no_mna(number_of_labels=2):
    """
    This function generates an MPLS stack only holding forwarding labels
    """  
    label_stack = []
    for n in range(number_of_labels):
        lse = MPLS_LSE(label=50 + n * 10, tc=7, bos=0, ttl=63)
        label_stack.append(lse)

    label_stack[-1].bos = 1
    return label_stack

def label_stack_hbh_select_psd(hbh_count, select_count, psd_count):
    """
    This function generates an MPLS stack with a forwarding label, followed by a Select NAS, multiple forwarding labels, a HBH NAS, some more forwarding labels, and PSD.
    """
    l1 = MPLS_LSE(label=50, tc=7, bos=0, ttl=63)
    l2 = MPLS_LSE(label=60, tc=7, bos=0, ttl=63)
    l3 = MPLS_LSE(label=70, tc=7, bos=0, ttl=63)
    l4 = MPLS_LSE(label=80, tc=7, bos=0, ttl=63)
    l5 = MPLS_LSE(label=90, tc=7, bos=0, ttl=63)

    hbh_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.HBH,unknown_action_handling=UnkownActionHandling.IGNORE)

    hbh_nas.initial_lse.reserved = 1

    for _ in range(hbh_count):
        hbh_nas.add_subsequent_opcode(opcode=64, data=2, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)
        
    hbh_nas.subsequent_opcodes[0].add_ancillary_data(0, 0)
    select_nas = NAS(initial_opcode=64, initial_data=0, scope=Scope.SELECT, unknown_action_handling=UnkownActionHandling.IGNORE)
    for _ in range(select_count):
        select_nas.add_subsequent_opcode(opcode=64, data=2, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0)

    psd_top = PSDTopHeader()
    for _ in range(psd_count):
        psd_top.add_ps_network_action(64, 0)

    psd_top.ps_network_actions[0].add_psd(0)
    psd_top.ps_network_actions[0].add_psd(0)
    psd_top.ps_network_actions[0].add_psd(0)
    psd_top.ps_network_actions[0].add_psd(0)
    psd_top.ps_network_actions[0].add_psd(0)


    label_stack = [l1, select_nas, l2, l3, hbh_nas, l4, l5], [psd_top]
    return label_stack

def label_stack_pmamm_isd(color):
    """
    :param color: 0 for color A, 2 for color B
    """
    # Forwarding Label 1
    l1 = MPLS_LSE(label=500, tc=7, bos=0, ttl=63)
    # Forwarding Label 2
    l2 = MPLS_LSE(label=600, tc=7, bos=0, ttl=63)
    # Forwarding Label 3
    l3 = MPLS_LSE(label=700, tc=7, bos=0, ttl=63)
    l4 = MPLS_LSE(label=800, tc=7, bos=0, ttl=63)
    l5 = MPLS_LSE(label=900, tc=7, bos=0, ttl=63)
    
    hbh_nas = NAS(initial_opcode=1, initial_data=0, scope=Scope.HBH,unknown_action_handling=UnkownActionHandling.IGNORE)
    hbh_nas.add_subsequent_opcode(opcode=43, data=2, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=color) # Two bits for flow id, last bit for packet loss measurement  

    label_stack = [l1,  l2, l3, l4, hbh_nas, l5]

    return label_stack


def convert_label_stack_to_lse(label_stack, psd=None):
    """
    This function converts the NAS data structures in a label stack into individual LSEs
    and sets the BoS bit accordingly.
    """

    all_lse = []
    for lse in label_stack:
        if isinstance(lse, MPLS_LSE):
            all_lse.append(lse)
        elif isinstance(lse, NAS):
            all_lse.append(lse.NSI)
            all_lse.append(lse.initial_lse)
            for sub in lse.subsequent_opcodes:
                all_lse.append(sub)
                for ad in sub.ancillary_data:
                    all_lse.append(ad)

    for lse in all_lse:
        lse.bos = 0
    all_lse[-1].bos = 1

    if psd:
        for ps in psd:
            if isinstance(ps, PSDTopHeader):
                all_lse.append(ps)
                for p in ps.ps_network_actions:
                    all_lse.append(p)
                    for d in p.psd:
                        all_lse.append(d)
    return all_lse

def print_label_stack(label_stack, psd=None):
    for lse in label_stack:
        print(lse)
    if psd:    
        for lse in psd:
            print(lse)    

def build_packet(all_lse):
    # Get the raw bytes 
    payload = [lse.get_payload() for lse in all_lse]
    
    # Build Ethernet and IP Header
    eth = Ether(src=get_if_hwaddr(interface), dst="08:00:00:00:02:22", type=0x8847)
    ip = IP(dst="10.0.2.2", src="10.0.1.1")
    pkt = eth

    for p in payload:
        custom_data_bytes = p.to_bytes(4, byteorder='big')
        # Create a raw layer
        raw_layer = Raw(load=custom_data_bytes)

        pkt = pkt / raw_layer
        
    # Add some random data
    payload = "a" * 18
    # Create P4TG UDP header
    pkt = pkt /ip / UDP(sport=50081, dport=50083) / payload
    
    return pkt


psd = []
label_stack = []
# Interface to send the packet from
interface = "ens18"

#label_stack = label_stack_hbh_select(5,7)
#label_stack = label_stack_hbh_only(7)
#label_stack = label_stack_select_only(2)
#label_stack = label_stack_no_mna(4)
label_stack = label_stack_pmamm_isd(4)
#label_stack, psd = label_stack_hbh_select_psd(3,4,1)

print_label_stack(label_stack)

all_lse = convert_label_stack_to_lse(label_stack, psd)
pkt = build_packet(all_lse)


# Send out the packet
sendp(pkt, iface=interface, count=1)