import sys
import socket
import dns.rdatatype
import requests
from pythonping import ping
from dns.resolver import Resolver, Timeout as dnsTimeout, NXDOMAIN, YXDOMAIN, NoAnswer, NoNameservers
from dns.reversename import from_address
from typing import List, Tuple

INTERNET_TEST = ["http://icann.org", "http://192.0.43.7", "http://www.eicar.org/download/eicar.com.txt"]


def bulk_ping(ips_list: List[str]) -> List[str]:
    """
    Perform a ping on a list of IPs.
    Parameters
    ----------
    ips_list: List[str]
        List of IPv4 and IPv6 address
    Returns
    -------
    responding_list: List[str]
        List of the IPv4 and IPv6 address that responds to the ping
    """
    if ips_list is None or len(ips_list) == 0:
        return None
    else:
        results: List[str] = list()
        for ip in ips_list:
            response = ping(ip, count=2, timeout=5)
            if response.success():
                results.append(ip)
        return results


def get_host_nameservers() -> List[str]:
    """
    Retrieve the DNS nameserver configured on the host
    Returns
    -------
    nameserver_list: List[str]
        List of the configured nameserver (IP as str)

    """
    return Resolver().nameservers


def get_host_search_domains() -> List[str]:
    """
    Retrieve the DNS search domain configured on the host
    Returns
    -------
    search_dmain_list: List[str]
        List of the search domain configured on the host
    """
    res_search_domain: List[str] = list()
    resolver: Resolver = Resolver()
    for domain in resolver.search:
        res_search_domain.append(domain.to_text())
    return res_search_domain


def dns_lookup(name: str, dns_type: str = dns.rdatatype.A, resolver: Resolver = Resolver()) -> str or None:
    """
    Perform a DNS lookup on a domain name and ip address
    Parameters
    ----------
    name : str
        The domain name or IP address on which perform the lookup
    dns_type : str
        Type of the record type we are looking for
    resolver: Resolver
        The resolver instance to use. Used for bulk operations.

    Returns
    -------
    result: str or None
        The resulting value of the query

    """
    if name is None or name == "" or type is None or type == "" or resolver is None:
        return None
    else:
        res_name = str()
        try:
            res_name = resolver.query(name, dns_type)[0].to_text()
        except dnsTimeout:
            print("The DNS request for \"{0}\" timeout.".format(name), file=sys.stderr)
        except NXDOMAIN:
            print("The name \"{0}\" does not exist.".format(name), file=sys.stderr)
        except YXDOMAIN:
            print("The name \"{0}\" is too long.".format(name), file=sys.stderr)
        except NoAnswer:
            print("There is no result for the name \"{0}\".".format(name), file=sys.stderr)
        except NoNameservers:
            print("No nameserver can answer the query for the name \"{0}\".".format(name), file=sys.stderr)

        return res_name


def dns_lookup_bulk(domain_list: List[str]) -> List[Tuple[str, str]] or None:
    """
    Perform a bulk DNS lookup for the given list of domain name
    Parameters
    ----------
    domain_list: List[str]
        List of domain nam as a space separated string
    Returns
    -------
    domains_lookup: List[Tuple[str, str]] or None
        List of resulting lookup as tuple[domain, lookup_result]
    """
    if domain_list is None or len(domain_list) == 0:
        return None
    resolver = Resolver()
    res_list: List[Tuple[str, str]] = list()
    for domain in domain_list:
        res = dns_lookup(domain, "A", resolver=resolver)
        res_list.append((domain, res))

    return res_list


def reverse_dns_lookup(ip: str) -> Tuple[str, str] or None:
    """
    Perform a reverse lookup on an IP
    Parameters
    ----------
    ip: str
        IP on which perform the reverse lookup

    Returns
    -------
        Resulting lookup as tuple[domain, reverse_lookup_result] or None
    """
    if ip is None or ip == "":
        return None, None
    else:
        arpa = from_address(ip).to_text()
        name = dns_lookup(arpa, "PTR")
        return arpa, name


def reverse_dns_lookup_bulk(ip_list: List[str]) -> List[Tuple[str, str]] or None:
    """
    Perform a Bulk reverse lookup for the given list of ips
    Parameters
    ----------
    ip_list : List[str]
        List of ips as a space separated string
    Returns
    -------
    ips_reverse_lookup: List[Tuple[str, str]] or None
        List of resulting reverse lookup as tuple[ips, reverse_lookup_result]
    """
    if ip_list is None or len(ip_list) == 0:
        return None
    else :
        resolver = Resolver()
        res_list: List[Tuple[str, str]] = list()
        for ip in ip_list:
            arpa = from_address(ip).to_text()
            name = dns_lookup(arpa, "PTR", resolver=resolver)
            res_list.append((arpa, name))
        return res_list


def open_connection(dest_ip: str, dest_port: int) -> bool:
    """
    This function tries to open a TCP socket on a given ip with a given port
    Parameters
    ----------
    dest_ip: str
        The server on which open the connection
    dest_port: int
        The socket target port

    Returns
    -------
    result: bool
        Boolean which tell if the connection can be established or not
    """
    if dest_ip is None or dest_ip == "" or dest_port is None or dest_port < 1:
        return False
    else:
        try:
            sock = socket.create_connection((dest_ip, dest_port), 5.0)
            sock.close()
            return True
        except OSError:
            return False


def get_accessible_service(ips_list: List[str], port: int) -> List[str] or None:
    """
    Perform a connection test tot service for designated ip
    Parameters
    ----------
    ips_list: List[str]
        String of IP as a space separated list
    port: int
        Port used by the service

    Returns
    -------
    result: List[str] or None
        List of ip with accessible service

    """
    if ips_list is None or len(ips_list) == 0 or port is None or port < 1:
        return None
    results: List[str] = list()
    for ip in ips_list:
        if open_connection(ip, port):
            results.append(ip)

    return results


def check_website_accessibility(url: str, proxies: dict = None, eicar: bool = False) -> bool:
    """
    Check if a website is accessible with the default network config
    Parameters
    ----------
    url : str
        Url of the website
    proxies: dict
        Dict that represent each proxy config : {"http": "http://user:pass@ip:port", "https": ...}
    eicar:
        Tell if the given url points to a EICAR file or not

    Returns
    -------
    result : bool
        Tells if the website is accessible

    """
    website_accessible: bool = False
    try:
        req = requests.get(url, proxies=proxies, timeout=5)
        if eicar:
            if "Virus" not in req.text:
                website_accessible = True
        else:
            if req.status_code != 407:
                website_accessible = True
    except requests.exceptions.ProxyError:
        print("The current proxy configuration does not work : \"{0}\".".format(proxies), file=sys.stderr)
        website_accessible = False
    except requests.exceptions.ConnectionError:
        print("No connection can be established to \"{0}\".".format(url), file=sys.stderr)
        website_accessible = False
    except requests.exceptions.Timeout:
        print("The request to  \"{0}\" timeout.".format(url), file=sys.stderr)
        website_accessible = False
    except requests.HTTPError as err:
        # website accessible but HTTP error
        print(err)
        website_accessible = True

    return website_accessible


def get_internet_access_state(proxy_host: str) -> str or None:
    """
    Perform the internet access test (test a public domain name, a public ip,...)
    Parameters
    ----------
    proxy_host : str
        Ip of the proxy

    Returns
    -------
    result: str or None
        text

    """
    websites = INTERNET_TEST
    if websites is None or websites == "":
        return None

    result: str = ""
    website_list: List[str] = websites
    if proxy_host != "" or proxy_host is None:
        proxies: dict = {'http': 'http://{0}:8000'.format(proxy_host), 'https': 'http://{0}:8000'.format(proxy_host)}
    else:
        proxies = None

    if check_website_accessibility(website_list[0]):
        result = result + "Websites are directly accessible via domain name.\n"
        if check_website_accessibility(website_list[1]):
            result = result + "Websites are directly accessible via IP.\n"
        else:
            result = result + "Websites are not directly accessible via IP.\n"
        if check_website_accessibility(website_list[2], eicar=True):
            result = result + "The EICAR file can be directly downloaded."
        else:
            result = result + "The EICAR file cannot be directly downloaded."
    elif check_website_accessibility(website_list[0], proxies=proxies):
        result = result + "Website are accessible via domain name with the proxy '{0}'.\n".format(proxy_host)
        if check_website_accessibility(website_list[1], proxies=proxies):
            result = result + "Website are accessible via IP with the proxy '{0}'.\n".format(proxy_host)
        else:
            result = result + "Websites are not accessible via IP with the proxy {0}.\n".format(proxy_host)

        if check_website_accessibility(website_list[2], proxies=proxies, eicar=True):
            result = result + "The EICAR file can be downloaded with the proxy '{0}'.".format(proxy_host)
        else:
            result = result + "The EICAR file cannot be downloaded with the proxy '{0}'.".format(proxy_host)
    else:
        result = result + "Website are not directly accessible via domain name or an authenticated proxy is required.\n"
        if check_website_accessibility(website_list[1]):
            result = result + "Website are directly accessible via IP."
        else:
            result = result + "Websites are not directly accessible via IP.\n"
    return result
