from ipaddress import IPv4Network, IPv4Address
from typing import List, Tuple
import subprocess
from scanner_lib.wrapper import generate_ip_list_str, list_online_ips_as_str, discovery_scan, vulnerability_scan, \
    website_screenshot
from scanner_lib.network_scanner.web_exposure import get_host_nameservers, get_host_search_domains, \
    get_accessible_service, dns_lookup, reverse_dns_lookup_bulk, dns_lookup_bulk, bulk_ping, \
    get_internet_access_state
from pathlib import Path

# Set some constants
ZSCALER_MAJOR_IPS = ["104.129.193.85", "104.129.195.85", "104.129.197.85", "104.129.193.102",
                     "104.129.197.102", "104.129.195.102"]
ZSCALER_DOMAIN = "zscaler.net"
PUBLIC_DNS_IPS = ["8.8.8.8", "9.9.9.9", "1.1.1.1", "8.8.4.4", "1.0.0.1", "223.5.5.5", "223.6.6.6",
                  "180.76.76.76"]
PUBLIC_DOMAINS = ["icann.org", "google.com", "baidu.com", "yandex.com"]
HTTP_PORTS = [80, 8080, 8000, 8001, 443, 4443, 8443]


def check_online_ips(target_network: IPv4Network, excluded_ips: List[IPv4Address]) -> str:
    """
    Perform a check to get all the available devices on the network
    Parameters
    ----------
    target_network : IPv4Network
        The target network for the scan
    excluded_ips : List[IPv4Address]
        List of IPs to exclude during the scan

    Returns
    -------
    ips_list: str
        List of available device ip as str

    """
    # generate list of ips for Nmap
    ip_list: str = generate_ip_list_str(target_network, excluded_ips)
    # Scan for up devices
    up_ip_list: str = list_online_ips_as_str(ip_list)
    # return the ips that are online
    return up_ip_list


def zscaler_detection(zscaler_ips: List[str], zscaler_domain: str) -> dict:
    """
    Perform a scan to test the accessibility to the Zscller cloud proxy service
    Parameters
    ----------
    zscaler_ips : List[str]
        The list of zscaler main IP as a space separated string
    zscaler_domain : str
        The Zscaler main domain name

    Returns
    -------
    result : dict
        Dict of DNS response and responding IP : {dns, ips}
    """
    results: dict = dict()
    results["dns_lookup"] = dns_lookup(zscaler_domain)
    results["ips_responding_ping"] = bulk_ping(zscaler_ips)
    return results


def nmap_scan(ip_list: str, with_vulnerability: bool, output_dir: str = None) -> Tuple[List[dict], List[dict]]:
    """
    Perform a Nmap scan (discovery, vulnerability)
    Parameters
    ----------
    ip_list : str
        List of IPs to scan
    with_vulnerability : bool
        Tell if the scan should include a vulnerability scan

    Returns
    -------
    results : Tuple[List[dict], List[dict]]
    """
    print("Running the namp discovery scan")
    discovery: List[dict] = discovery_scan(ip_list, output_dir)
    vulnerability: List[dict] = None
    port_list: set = set()
    for host_dict in discovery:
        for entry in host_dict.values():
            if entry.get("tcp") is not None:
                for key in entry["tcp"].keys():
                    port_list.add(key)
    ports = None
    if len(port_list) != 0:
        ports = ",".join(str(x) for x in port_list)

    if with_vulnerability:
        print("Running the nmap vulnerability scan")
        vulnerability = vulnerability_scan(ip_list, output_dir, ports)
    print("Done scanning with nmap")
    return discovery, vulnerability


def dns_scan(ip_list_str: List[str]) -> dict:
    """
    Perform a DNS scan on the network and host
    Parameters
    ----------
    ip_list_str : List[str]
        List of IP on which perform a reverse DNS query

    Returns
    -------

    """
    results: dict = dict()
    results["nameserver"] = get_host_nameservers()
    results["search_domain"] = get_host_search_domains()
    results["public_dns_access"] = get_accessible_service(PUBLIC_DNS_IPS, 53)
    results["proxy"] = dns_lookup("proxy")
    results["reverse_lookup"] = reverse_dns_lookup_bulk(ip_list_str)
    results["public_domain_query"] = dns_lookup_bulk(PUBLIC_DOMAINS)
    return results


def internet_scan(proxy_host: str) -> dict:
    """
    Perform an internet scan on the network
    Parameters
    ----------
    proxy_host : str
        IP adresse of the proxy
    Returns
    -------
    result : dict
    """
    results: dict = dict()
    results["internet_access"] = get_internet_access_state(proxy_host)
    results["zscaler_detection"] = zscaler_detection(ZSCALER_MAJOR_IPS, ZSCALER_DOMAIN)
    return results


def read_dmesg() -> str:
    """
    Read the content of the DMESG cli tool
    Returns
    -------
    str
    """
    proc = subprocess.run(["dmesg", "--ctime"], stdout=subprocess.PIPE, universal_newlines=True)
    return proc.stdout


def perform_tcpdump(working_dir: str) :
    """
    Perform a tcpdump and save the result in a designated directory
    Parameters
    ----------
    working_dir : str
        Path to the directory where the file will be saved
    Returns
    -------

    """
    proc = subprocess.run(["timeout", "120", "tcpdump", "-i", "enp0s3", "-s", "0", "-w", working_dir + "/net-dump.pcap"])


def perform_webcreenshot(nmap_disco: List[dict], output_dir: dir):
    """
    Perform a screenshot on each webserver discovered.
    Parameters
    ----------
    nmap_disco : list[dict]
        Results from the nmap discovery scan
    output_dir : str
        Path to the directory where the screenshots will be stored

    Returns
    -------

    """
    Path(output_dir + "/webscreenshot").mkdir(parents=True, exist_ok=True)

    urls_list: List[str] = list()
    for entry in nmap_disco:
        for address, nmap_dict in entry.items():
            if nmap_dict.get("tcp") :
                for key, val in nmap_dict["tcp"].items():
                    if key in HTTP_PORTS:
                        urls_list.append("http://{0}:{1}".format(address, key))

    website_screenshot(urls_list, output_dir + "/webscreenshot")


if __name__ == "__main__":
    nmap_scan('10.210.114.166', True)
