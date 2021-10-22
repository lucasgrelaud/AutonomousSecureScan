import re
import netifaces
from ipaddress import IPv4Address, IPv4Network, IPv4Interface, IPv6Interface
from typing import List


class Interface:
    """
    Attributes
    ----------
    name: str
        Name of the network interface
    mac : str
        Mac address of the network interface
    ipv4_interfaces: List[IPv4Interface]
        List of IPv4 network recognised for this network interface
    ipv6_interfaces: List[IPv6Interface]
            List of IPv6 network recognised for this network interface
    """
    name: str
    mac: str
    ipv4_interfaces: List[IPv4Interface]
    ipv6_interfaces: List[IPv6Interface]
    gateways: dict

    def __init__(self, name):
        self.name = name
        self.mac = str()
        self.ipv4_interfaces = list()
        self.ipv6_interfaces = list()
        self.gateways = dict()

    def __str__(self):
        return "Interface: {0}, MAC: {1}, IPv4: {2}, IPv6: {3}" \
            .format(self.name, self.mac, self.ipv4_interfaces, self.ipv6_interfaces)


def calculateIPv4CIDR(netmask: str) -> int:
    """
    Calculate the CIDR of a IPv4 network using its netmask

    Parameters
    ----------
    netmask: str
        The fully composed netmask (e.G: 255.255.255.0)

    Returns
    -------
    ipv4_cidr: int
        The resulting CIDR
    """
    if netmask is None or netmask == "":
        return -1
    elif not re.match(
            r"^(255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252)",
            netmask):
        return -1
    else:
        return sum([bin(int(x)).count("1") for x in netmask.split(".")])


def calculateIPv6CIDR(netmask: str) -> int:
    """
        Calculate the CIDR of a IPv6 network using its netmask

        Parameters
        ----------
        netmask: str
            The fully composed netmask (e.G: 255.255.255.0)

        Returns
        -------
        ipv6_cidr: int
            The resulting CIDR
        """
    if netmask is None:
        return -1
    elif re.match(r".*[g-zG-Z].*", netmask) is not None:
        return -1
    elif not re.match(
            r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
            netmask):
        return -1
    else:
        res = 0
        for x in netmask.split(':'):
            if x != '':
                res += bin(int("{0}".format(x), 16)).count("1")
        return res


def get_active_interfaces() -> List[Interface]:
    """
    list get all network interface (except the loopback one) available on the device.

    Returns
    -------
    interfaces : List[Interface]
        List of Interface
    """
    results: List[Interface] = list()
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if netifaces.ifaddresses(interface).get(netifaces.AF_INET) is not None or netifaces.ifaddresses(interface).get(
                netifaces.AF_INET6) is not None:
            iface = Interface(interface)
            for af_type, af_list in netifaces.ifaddresses(interface).items():
                if af_type == netifaces.AF_INET:
                    for af_dict in af_list:
                        cidr = calculateIPv4CIDR(af_dict.get("netmask"))
                        iface.ipv4_interfaces.append(IPv4Interface("{0}/{1}".format(af_dict.get("addr"), cidr)))
                if af_type == netifaces.AF_INET6:
                    for af_dict in af_list:
                        cidr = af_dict.get("netmask").split("/")[1]
                        iface.ipv6_interfaces.append(
                            IPv6Interface("{0}/{1}".format(af_dict.get("addr").split('%')[0], cidr))
                        )
                if af_type == netifaces.AF_LINK:
                    for af_dict in af_list:
                        iface.mac += af_list[0].get("addr")

            gateway_list: List[tuple] = list()
            for gateway in netifaces.gateways()[2]:
                if gateway[1] == iface.name:
                    gateway_list.append(gateway)
            if len(gateway_list) != 0:
                iface.gateways = gateway_list

            results.append(iface)

    return results if len(results) > 1 else None


def get_ipv4_networks(interfaces: List[Interface] = None) -> List[IPv4Network]:
    """
    Get all IPv4 networks available in the list of Interfaces
    Parameters
    ----------
    interfaces : List[Interfaces]
        List of Interfaces (usually generated by the host config)
    Returns
    -------
    ipv4_networks : List[IPv4Network]
        List of networks
    """
    if interfaces is None:
        interfaces = get_active_interfaces()

    res_ipv4_networks: list = list()

    for interface in interfaces:
        if interface.name != "lo":
            for ipv4_interface in interface.ipv4_interfaces:
                res_ipv4_networks.append(ipv4_interface.network)

    return res_ipv4_networks


def get_ipv4_address(interfaces: List[Interface] = None) -> List[IPv4Address]:
    if interfaces is None:
        interfaces = get_active_interfaces()

    res_ipv4_address: list = list()

    for interface in interfaces:
        if interface.name != "lo":
            for ipv4_network in interface.ipv4_interfaces:
                res_ipv4_address.append(ipv4_network.ip)

    return res_ipv4_address


def get_ipv4_network_hosts(networks: List[IPv4Network] = None) -> List[IPv4Address]:
    """
    Get all IPv4 address from a list of IPv4 network
    Parameters
    ----------
    networks: List[IPv4Network]
        List of IPv4Network from which extract the IPv4 address
    networks

    Returns
    -------
    ipv4_address: List[IPv4Address]

    """
    if networks is None:
        networks = get_ipv4_networks()
    res_ipv4_address: List[IPv4Address] = list()
    for network in networks:
        res_ipv4_address.append(network.hosts())

    return res_ipv4_address

