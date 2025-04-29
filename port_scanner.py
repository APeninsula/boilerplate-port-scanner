import socket
import common_ports

def get_open_ports(target, port_range, verbose = False):
    open_ports = []

    is_valid_target = validate_target(target)
    if is_valid_target == 2:
        return "Error: Invalid hostname"
    elif is_valid_target == 1:
        return "Error: Invalid IP address"
    converted_ipv4address = is_valid_target
    try:
        for port_no in range(port_range[0]-1, port_range[1]+1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(.5)
            s_connection = s.connect_ex((converted_ipv4address, port_no))
            if s_connection == 0:
                open_ports.append(port_no)
            s.close()
        ret_val = None
        if verbose == False:
            ret_val = open_ports
        else:
            name_space = get_hostname(converted_ipv4address)
            ret_val = build_open_ports_string(name_space, converted_ipv4address, open_ports)

        return(ret_val)
    except socket.error as e:
        return e.strerror


def build_open_ports_string(url_target:str, ipv4_target:str, open_ports=[]):
    # May need to use getAddressInfo and carve out information from that function call.
    # name_space = url_target if ipv4_target != url_target else ""
    ret_string = "Open ports for {ipv4}".format(ipv4=ipv4_target)if not url_target else "Open ports for {url} ({ipv4})".format(url=url_target,ipv4=ipv4_target)
    ret_string+= "\nPORT     SERVICE"
    ports_length = len(open_ports)
    if ports_length > 1:
        for i in open_ports:
            service = common_ports.ports_and_services[i]
            ret_string+= "\n{port}".format(port=i) + adjust_spaces(i) + service
    elif ports_length == 1:
        i = open_ports[0]
        service = common_ports.ports_and_services[i]
        ret_string+= "\n{port}".format(port=i) + adjust_spaces(i) + service
    return ret_string

def get_hostname(ip_address:str):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.error as e:
        print(e)
        return ""

def adjust_spaces(number, spaces=8):
    if number >= 10:
        spaces -=1
    if number>= 100:
        spaces -=1
    if number>=1000:
        spaces -=1
    
    return (" "*spaces)
def validate_target(target:str):
    # Need to check to see if it is a potentially valid IP address first
    # Next, need to validate if it is a potentially valid Hostname
    # Should return ipv4address if valid, 1 if invalid IP Address, 2 if invalid Hostname

    split_target = target.split('.')
    is_ipv4 = True
    if len(split_target)==4:
        # Could be an IP address
        for group in split_target:
            if not group.isdigit():
                is_ipv4 = False
                break
    else:
        is_ipv4 = False
    if is_ipv4:
        try:
            socket.inet_aton(target)
        except socket.error as e:
            print(e)
            return 1
        else:
            return target
    else:
        try:
            ipv4 = socket.gethostbyname(target)
        except socket.error as e:
            print(e)
            return 2
        else:
            return ipv4