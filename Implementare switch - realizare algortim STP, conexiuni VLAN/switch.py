#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import re
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from struct import pack

class BPDU_package:
    def __init__(self, root_bridge_ID, own_bridge_ID, sender_path_cost):
        # Set root bridge ID
        self._set_root_bridge_ID(root_bridge_ID)
        # Set own bridge ID
        self._set_own_bridge_ID(own_bridge_ID)
        # Set sender path cost
        self._set_sender_path_cost(sender_path_cost)

    def _set_root_bridge_ID(self, root_bridge_ID):
        self.root_bridge_ID = root_bridge_ID

    def _set_own_bridge_ID(self, own_bridge_ID):
        self.own_bridge_ID = own_bridge_ID

    def _set_sender_path_cost(self, sender_path_cost):
        self.sender_path_cost = sender_path_cost

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu(root_bridge_ID, own_bridge_ID, sender_path_cost):
    header = pack("!BBBBBB", 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
    mac_address = get_switch_mac()
    ethertype = pack("!H", 33)
    llc_header = pack("!BBB", 0x42, 0x42, 0x03)
    padding = pack("!BBBB", 0x00, 0x00, 0x00, 0x00)
    bridge_info = pack("i", root_bridge_ID) + pack("i", own_bridge_ID) + pack("i", sender_path_cost)

    return header + mac_address + ethertype + llc_header + padding + bridge_info

def send_bdpu_every_sec(bpdu_object, interfaces, vlan_table):
    while True:
        # TODO Send BPDU every second if necessary
        if bpdu_object.own_bridge_ID == bpdu_object.root_bridge_ID:
            # Parse the VLAN table and send BPDU to all trunk interfaces
            i = 0
            while i < len(interfaces):
                interface_test = interfaces[i]
                # Check if the interface is in the VLAN table and is a trunk
                if interface_test in vlan_table:
                    if vlan_table[interface_test] == "T":
                        # Create and send the BPDU package
                        bpdu_pack = create_bpdu(bpdu_object.own_bridge_ID, bpdu_object.own_bridge_ID, 0)
                        send_to_link(interface_test, 33, bpdu_pack)
                i += 1
        print(bpdu_object.root_bridge_ID)
        time.sleep(1)

def is_unicast(mac_address):
    # Split the MAC address and check if the first byte is even
    bytes = mac_address.split(':')
    first = int(bytes.pop(0), 16)

    if first & 1 != 0:
        return False
    return True
    
def get_vlan_id(interface, vlan):
    # Get the vlan id of the interface
    return int(vlan[get_interface_name(interface)])

def read_config_switch(switch_id, interface_id):
    # Open the configuration file for the specified switch number
    with open("configs/switch" + switch_id + ".cfg", "r") as config_file:
        content_lines = config_file.readlines()  # Read all lines into a list
        
        line_number = 0  # Initialize line counter
        priority = 0  # Variable to store the priority value
        vlan_parse = {}  # Initialize vlan_parse dictionary
        
        # Use a while loop to iterate through each line in the file
        while line_number < len(content_lines):
            content = content_lines[line_number].strip()  # Remove any extra whitespace
            if line_number == 0:
                # The first line contains the priority value, convert it to an integer
                priority = int(content)
            else:
                # For other lines, split the content by space
                parts = content.split(" ")
                # Map the parsed VLAN to the port using the port_id dictionary
                vlan_parse[interface_id[parts[0]]] = parts[1]
            
            # Move to the next line
            line_number += 1
            
    # Return the VLAN configuration and priority value
    return vlan_parse, priority

def delete_vlan_tag(data):
    # Remove the VLAN tag from the data
    return data[0:12] + data[16:]

def send_from_acces(data, interface, length, vlan_parse, ports_state, interface_final):
    # Check if the destination is a trunk (access to trunk)
    if vlan_parse[interface_final] == "T":
        # Check if the port is not blocked
        if ports_state[interface_final] != "BLOCKED":
            data = data[0:12] + create_vlan_tag(int(vlan_parse[interface])) + data[12:]
            send_to_link(interface_final, length + 4, data)
    # Access to access
    else:
        # Check if the VLANs match
        if int(vlan_parse[interface_final]) == int(vlan_parse[interface]):
            # Data is the data with no header
            data = data
            send_to_link(interface_final, length , data)            

def send_from_trunk(data, interface, length, vlan_parse, ports_state, interface_final, vlan_id):
    # Check if the destination is a trunk (trunk to trunk)
    if vlan_parse[interface_final] == "T":
        # Check if the port is not blocked
        if ports_state[interface_final] != "BLOCKED":
            data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
            send_to_link(interface_final, length + 4, data)
    # Trunk to access
    else:
        # Check if the VLANs match
        if int(vlan_parse[interface_final]) == vlan_id:
            # Data is the data with no header
            data = data
            send_to_link(interface_final, length, data)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    mac_table = {}
    vlan_parse = {}
    ports_state = {}
    interface_id = {}

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    
    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))
        interface_id[get_interface_name(i)] = i

    # Read the configuration file for the switch
    vlan_parse, priority = read_config_switch(switch_id, interface_id)

    # The variable ok is used to check if the switch is the root bridge
    ok = 1
    # The variable root_port is used to store the root port
    root_port = -1

    # Set the state of the ports to BLOCKED if they are in the VLAN table
    i = 0
    while i < len(interfaces):
        interface_test = interfaces[i]
        if interface_test in vlan_parse:
            if vlan_parse[interface_test] == "T":
                ports_state[interface_test] = "BLOCKED"
        i += 1

    init = BPDU_package(priority, priority, 0)

    # Check if it is the root bridge and set all ports to DESIGNATED
    if init.own_bridge_ID == init.root_bridge_ID:
        i = 0
        while i < len(interfaces):
            interface_test = interfaces[i]
            ports_state[interface_test] = "DESIGNATED"
            i += 1
    
    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bdpu_every_sec, args = (init, interfaces, vlan_parse))
    t.start()


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

        if dest_mac == "01:80:c2:00:00:00":
            root_bridge_id = int.from_bytes(data[21:25], "little")
            own_bridge_id = int.from_bytes(data[25:29], "little")
            sender_path_cost = int.from_bytes(data[29:33], "little")

            package = BPDU_package(root_bridge_id, own_bridge_id, sender_path_cost)

            # Check if the BID is smaller than the current root bridge ID
            if package.root_bridge_ID < init.root_bridge_ID:
                init.root_bridge_ID = package.root_bridge_ID
                init.sender_path_cost = package.sender_path_cost + 10
                root_port = interface
                
                # Check if it is the root bridge
                if ok == 1:
                    # Set all ports to BLOCKED except the root port
                    i = 0
                    while i < len(interfaces):
                        interface_test = interfaces[i]
                        if interface_test != interface and vlan_parse[interface_test] == "T":
                            ports_state[interface_test] = "BLOCKED"
                        i += 1
                    ok = 0

                # Set the root port to DESIGNATED
                if ports_state[interface] == "BLOCKED":
                    ports_state[interface] = "LISTENING"
                
                # Send BPDU to all trunk interfaces
                i = 0
                while i < len(interfaces):
                    interface_test = interfaces[i]
                    if vlan_parse[interface_test] == "T":
                        length = 33
                        send_to_link(interface_test, length, create_bpdu(package.root_bridge_ID, init.own_bridge_ID, init.sender_path_cost))
                        package.own_bridge_ID = init.own_bridge_ID
                        package.sender_path_cost = init.sender_path_cost
                    i += 1
            # Check if the root BID is equal to the current root bridge ID
            elif package.root_bridge_ID == init.root_bridge_ID:
                # Check if the path cost is smaller than the current path cost
                if package.sender_path_cost + 10 < init.sender_path_cost:
                    if interface == root_port:
                        init.sender_path_cost = package.sender_path_cost + 10
                # Check if the port is not the root port
                elif interface != root_port:
                    if package.sender_path_cost > init.sender_path_cost and ports_state[interface] != "DESIGNATED":
                        ports_state[interface] = "LISTENING"
            # Check if the own BID is equal to the current own bridge ID and set the port to BLOCKED
            elif package.own_bridge_ID == init.own_bridge_ID:
                ports_state[interface] = "BLOCKED"
            else:
                # Discard the BPDU
                continue

            # Check if the own BID is equal to the root bridge ID and set all ports to DESIGNATED
            if init.own_bridge_ID == init.root_bridge_ID:
                i = 0
                while i < len(interfaces):
                    interface_test = interfaces[i]
                    ports_state[interface_test] = "DESIGNATED"
                    i += 1
        else:
            # Check if it is trunk and remove the VLAN tag
            if vlan_parse[interface] == "T":
                length = length - 4
                data = delete_vlan_tag(data)

            mac_table[src_mac] = interface
            # Check if the destination MAC address is unicasted
            if is_unicast(dest_mac):
                # Check if the destination MAC address is in the MAC table
                if dest_mac in mac_table:
                    # Check if the source is the type trunk
                    if vlan_parse[interface] == "T":
                        send_from_trunk(data, interface, length, vlan_parse, ports_state, mac_table[dest_mac], vlan_id)
                    # Check if the source is the type access
                    else:
                        send_from_acces(data, interface, length, vlan_parse, ports_state, mac_table[dest_mac])
                else:
                    # Broadcast the frame to all interfaces except the incoming interface
                    for interface_final in interfaces:
                        if interface_final != interface:
                            # Check if the source is the type trunk
                            if vlan_parse[interface] == "T":
                                send_from_trunk(data, interface, length, vlan_parse, ports_state, interface_final, vlan_id)
                            # Check if the source is the type access
                            else:
                                send_from_acces(data, interface, length, vlan_parse, ports_state, interface_final)
            else:
                # Broadcast the frame to all interfaces except the incoming interface
                for interface_final in interfaces:
                    if interface_final != interface:
                        # Check if the source is the type trunk
                        if vlan_parse[interface] == "T":
                            send_from_trunk(data, interface, length, vlan_parse, ports_state, interface_final, vlan_id) 
                        # Check if the source is the type access
                        else:
                            send_from_acces(data, interface, length, vlan_parse, ports_state, interface_final)       
if __name__ == "__main__":
    main()
