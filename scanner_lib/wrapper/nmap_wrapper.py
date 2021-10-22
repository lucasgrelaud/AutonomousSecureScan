import nmap
from ipaddress import IPv4Network, IPv4Address
from progress.bar import Bar
from typing import List


def generate_ip_list_str(network: IPv4Network, excluded_ips: List[IPv4Address] = None) -> str:
    """
    Generate a list (string) of IP based on a given network and a exclusion list
    Parameters
    ----------
    network : IPv4Network
        The targer network
    excluded_ips : List[IPv4Address]
        List of IPv4 address that need to be excluded (if present in te target network)
    Returns
    -------
    ipv_4_list : str
c   """
    res_list: List[IPv4Address] = list(network.hosts())
    res_str: str = str()
    if excluded_ips is not None:
        for ip in excluded_ips:
            try:
                res_list.remove(ip)
            except ValueError:
                continue
    for ip in res_list:
        res_str += "{0} ".format(ip.compressed)
    return res_str[:-1]


def list_online_ips_as_str(hosts_ips: str) -> str:
    """
    List IPs responding to a nmap probe (-sn arg)
    Parameters
    ----------
    hosts_ips : str
        IPlist (given by generate_ip_list_str)

    Returns
    -------
    ips_list : str
    """
    res_list: list = list()
    res_str: str = str()
    scanner = nmap.PortScannerYield()
    with Bar("Checking for online ips", max=len(hosts_ips.split(" "))) as bar:
        for progressive_result in scanner.scan(hosts=hosts_ips, ports=None, arguments='-sn', sudo=False):
            res_list.append(progressive_result)
            bar.next()
    for res in res_list:
        if res[1].get("nmap") is not None:
            if res[1]["nmap"].get("scanstats") is not None:
                if res[1]["nmap"]["scanstats"]["uphosts"] == '1':
                    res_str += "{0} ".format(res[0])
    return res_str[:-1]


def discovery_scan(hosts_ips: str, output_dir: str = None, ports: str = None) -> List[dict]:
    """
    Perform a discovery scan with nmap
    Parameters
    ----------
    hosts_ips : str
        List of IP to scan

    Returns
    -------
    results : List[dict]
        List of nmap result for each IP

    """
    args = '--script discovery'
    if output_dir is not None:
        args += " -oN " + output_dir + "/nmap_disco.txt"
    res_list: List[dict] = list()
    scanner = nmap.PortScanner()
    res_list.append(scanner.scan(hosts=hosts_ips, ports=ports, arguments=args, sudo=True)["scan"])

    return res_list


def vulnerability_scan(hosts_ips: str, output_dir: str = None, ports: str = None) -> List[dict]:
    """
    Perform a vulnerability scan with nmap
    Parameters
    ----------
    hosts_ips : str
        List of IP to scan

    Returns
    -------
    results : List[dict]
        List of nmap result for each IP

    """
    args = '--script vuln '
    if output_dir is not None:
        args += " -oN " + output_dir + "/nmap_vuln.txt"
    res_list: List[dict] = list()
    scanner = nmap.PortScanner()
    res_list.append(scanner.scan(hosts=hosts_ips, ports=ports, arguments=args, sudo=True)["scan"])
    #scanner = nmap.PortScannerYield()
    #with Bar("Vulnerability scan", max=len(hosts_ips.split(" ")),
    #         suffix='%(index)d / %(max)d - Have a break, it may take a while!') as bar:
    #    for res in scanner.scan(hosts=hosts_ips, ports=None, arguments=args, sudo=True):
    #        if res[1].get("scan") is not None:
    #            if res[1]["scan"].get(res[0]) is not None:
    #                res_list.append(res[1]["scan"].get(res[0]))
    #        bar.next()
    return res_list


if __name__ == "__main__" :

    scanner = nmap.PortScanner()
    nmap_res = scanner.scan(hosts="10.210.114.162", ports=None, arguments="--script discovery", sudo=True)
    print(nmap_res)


# TODO : add global support for UDP