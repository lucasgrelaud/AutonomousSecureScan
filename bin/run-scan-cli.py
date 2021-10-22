#!/bin/python3
import json
import os
import sys
import tarfile
import tempfile
import gnupg
from datetime import datetime
from ipaddress import IPv4Interface, IPv4Address, AddressValueError, NetmaskValueError
from pathlib import Path
from typing import List
from scanner_lib import ExitCode
from scanner_lib.network_scanner.interfaces import get_ipv4_address, Interface
from scanner_lib.scanner import nmap_scan, check_online_ips, dns_scan, internet_scan, read_dmesg, perform_tcpdump, \
    perform_webcreenshot

SCANNER_VERSION = "1.0.0"
SECURITY_TEAM_EMAIL = "sec_it@example.com"


class ScannerConfiguration:
    scanner_version: str
    scan_target_network: IPv4Interface
    scan_exclude_ips: List[IPv4Interface]
    scan_datetime: datetime
    scan_output_dir: str
    interfaces: List[Interface]

    def __init__(self):
        self.scan_target_network = None
        self.scan_exclude_ips = None
        self.scanner_version = SCANNER_VERSION
        self.scan_datetime = None
        self.scan_output_dir = None
        self.interfaces = list()

    def to_dict(self):
        config_dict: dict = dict()
        config_dict["datetime"] = self.scan_datetime.strftime("%Y-%m-%d %Hh%Mm%Ss")
        config_dict["excluded_ips"] = ",".join(map(lambda x: str(x), self.scan_exclude_ips))
        config_dict["target_network"] = self.scan_target_network.with_prefixlen
        config_dict["scanner_version"] = self.scanner_version
        config_dict["interfaces"] = self.interfaces
        return config_dict


class ScannerResults:
    nmap_disco: List[dict]
    nmap_vuln: List[dict]
    internet_scan: dict
    dns_scan: dict
    dmesg: str

    def __init__(self):
        self.nmap_disco = None
        self.nmap_vuln = None
        self.internet_scan = None
        self.dns_scan = None
        self.dmesg = None

    def to_dict(self) -> dict:
        results: dict = dict()
        results["dmesg"] = self.dmesg
        results["dns_scan"] = self.dns_scan
        results["internet_scan"] = self.internet_scan
        results["nmap_disco"] = self.nmap_disco
        results["nmap_vuln"] = self.nmap_vuln

        return results


def scanner_init(scan_target_network: IPv4Interface, scan_exclude_ips: List[IPv4Address],
                 scan_output_dir: str) -> ScannerConfiguration:
    # Init of the configuration class
    scanner_config: ScannerConfiguration = ScannerConfiguration()

    # Test for a proper network configuration
    scanner_host_address = get_ipv4_address()
    if len(scanner_host_address) < 1:
        print("There is no valid network connection on this computer.\n"
              "Please check it and restart the scanner. \nExiting...", file=sys.stderr)
        exit(ExitCode.NETWORKING_ERROR)

    if os.geteuid() != 0:
        print("This utility requires administrative rights to perform its scan.\n "
              "Please restart this utility with \"sudo\"", file=sys.stderr)
        exit(ExitCode.NON_ROOT_LAUNCH)


    print(
        "********************************************************************************\n"
        "********************************************************************************\n"
        "*                                                                              *\n"
        "*              Autonomous Secure Scan : Automatic scan script                  *\n"
        "*                                                                              *\n"
        "********************************************************************************\n"
        "********************************************************************************\n"
        "Warning : this scipt will run tools that may generate issues on your\n"
        "local servers !\n"
        "If your are not allowed or don't want to proceed stop immediately.\n\n"
    )
    # Ask if the operator wants to proceed
    if input("Do you want to continue ? [y/N]: ").lower().strip(' \t\n\r') != "y":
        print("Closing...")
        exit(ExitCode.NORMAL)

    # If no scan_network passed as args ask for one, else validate the choice
    if scan_target_network is None:
        scan_target_network = ask_for_network()
    while input("You have set the target IPv4 network to \"{0}\", is it right ? [y/N]: ".format(
            scan_target_network.with_prefixlen)).lower().strip(' \t\n\r') != "y":
        scan_target_network = ask_for_network()

    scanner_config.scan_target_network = scan_target_network

    # If no scan_exceptions passed as args ask for one, else validate the choice
    if len(scan_exclude_ips) == 0:
        scan_exclude_ips = ask_for_excluded_ips()
    while True:
        print("Here are the IP(s) you have excluded from the scan:")
        if len(scan_exclude_ips) == 0:
            print("\t• No exclusion")
        for ip in scan_exclude_ips:
            print("\t• {0}".format(ip.compressed))

        if input("Is it right ? [y/N] :").lower().strip(' \t\n\r') != "y":
            scan_exclude_ips = ask_for_excluded_ips()
        else:
            break
    # Automatically exclude the scanner_lib IP
    scan_exclude_ips.extend(get_ipv4_address())
    scanner_config.scan_exclude_ips = scan_exclude_ips

    # Configure other settings
    scanner_config.scan_datetime = datetime.now()
    scanner_config.scan_output_dir = scan_output_dir + "/SecureScan_" + scanner_config.scan_datetime.strftime(
        "%Y-%m-%d_%Hh%M")

    return scanner_config


def ask_for_network() -> IPv4Interface:
    loop: bool = True
    scan_target_network: IPv4Interface = None
    while loop:
        print("Please enter the network you want to scan.\n"
              "Example: 192.168.1.1/24")
        input_str = input("\tNetwork : ")
        try:
            scan_target_network = IPv4Interface(input_str)
        except AddressValueError:
            print("The network \"{0}\" does not have a valid IPv4 address.".format(input_str), file=sys.stderr)
        except NetmaskValueError:
            print("The network \"{0}\" does not have a valid IPv4 CIDR.".format(input_str), file=sys.stderr)
        if scan_target_network is not None and int(scan_target_network.with_prefixlen.split('/')[1]) < 24:
            print("To prevent performance issues, only a CIDR superior or equal to 24 is authorised.",
                  file=sys.stderr)
        elif scan_target_network is not None and int(scan_target_network.with_prefixlen.split('/')[1]) > 30:
            print("A network have at least 2 IPs => min CIDR : 30 .",
                  file=sys.stderr)
        elif scan_target_network is not None and 24 <= int(scan_target_network.with_prefixlen.split('/')[1]) <= 30:
            loop = False
    return scan_target_network


def ask_for_excluded_ips() -> List[IPv4Address]:
    loop: bool = True
    scan_exclude_ips: List[IPv4Address] = list()
    while loop:
        error: bool = False
        print("Please enter the IP(s) you want to exclude from the scan. Empty for no exclusion\n"
              "Example: 192.168.1.1, 192.168.1.2")
        input_str = input("\tIP(s) : ")

        if input_str is "":
            loop = False
            continue
        for ip in input_str.split(","):
            try:
                scan_exclude_ips.append(IPv4Address(ip.strip(' \t\n\r')))
            except AddressValueError:
                print("The excluded IPv4 \"{0}\" is not valid.".format(ip))
                error = True
                break
        if error:
            scan_exclude_ips = list()
        else:
            loop = False

    return scan_exclude_ips


def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")


def create_report_dict(scanner_config: ScannerConfiguration, scanner_results: ScannerResults) -> dict:
    result: dict = dict()
    result["scanner_config"] = scanner_config.to_dict()
    result["scanner_result"] = scanner_results.to_dict()
    return result


def create_gpg_archive(output_dir: str) -> bool:
    try:
        with tarfile.open(output_dir + ".tgz", "w:gz") as tarball:
            tarball.add(output_dir, arcname=os.path.basename(output_dir))
    except tarfile.ReadError:
        print("The directory {0} cannot be opened for compression".format(output_dir), file=sys.stderr)
        print("Please manually compress the folder \"{0}\" and send it to {1}"
              .format(output_dir, SECURITY_TEAM_EMAIL))
        exit(ExitCode.TAR_ERROR)
    except tarfile.CompressionError:
        print("Something went wrong while compressing the report", file=sys.stderr)
        print("Please manually compress the folder \"{0}\" and send it to {1}"
              .format(output_dir, SECURITY_TEAM_EMAIL))
        exit(ExitCode.TAR_ERROR)
    except tarfile.TarError:
        print("Something went wrong with the TAR module", file=sys.stderr)
        print("Please manually compress the folder \"{0}\" and send it to {1}"
              .format(output_dir, SECURITY_TEAM_EMAIL))


    gpg: gnupg.GPG = gnupg.GPG()
    with open(output_dir + ".tgz", "rb") as tarball:
        status = gpg.encrypt_file(tarball, SECURITY_TEAM_EMAIL, output=output_dir + ".gpg")
        print("Please send the encrypted archive to {0}."
              .format(SECURITY_TEAM_EMAIL))
        return status.ok


if __name__ == "__main__":
    import argparse
    from argparse import RawTextHelpFormatter

    parser = argparse.ArgumentParser("Autonomous information system audit suite.",
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("-t", "--target", type=str, default=None,
                        help="The IPv4 network on which perform the network scan.\n"
                             "Example : \"-t 192.168.1.1/24\"")
    parser.add_argument("-e", "--exclude", type=str, default=None, action='append',
                        help="The IPv4 address to exclude from the scan. You can set multiple IPs.\n"
                             "Example : \"-e 192.168.1.1 -e 192.168.1.2\"")
    parser.add_argument("-o", "--output-dir", type=dir_path, default=tempfile.gettempdir(),
                        help="The full path of directory where the results will be stored.\n")
    args = parser.parse_args()

    arg_target_network: IPv4Interface = None
    if args.target is not None:
        try:
            arg_target_network = IPv4Interface(args.target)
        except AddressValueError:
            print("The network \"{0}\" does not have a valid IPv4 address.".format(args.target), file=sys.stderr)
            exit(ExitCode.BAD_TARGET_NETWORK)
        except NetmaskValueError:
            print("The network \"{0}\" does not have a valid IPv4 CIDR.".format(args.target), file=sys.stderr)
            exit(ExitCode.BAD_TARGET_NETWORK)

        if int(arg_target_network.with_prefixlen.split('/')[1]) < 24:
            print("To prevent performance issues, only a CIDR superior or equal to 24 is authorised.",
                  file=sys.stderr)
            exit(ExitCode.BAD_TARGET_NETWORK)

    arg_exclude_ips: List[IPv4Address] = list()
    if args.exclude is not None:
        for address in args.exclude:
            try:
                arg_exclude_ips.append(IPv4Address(address))
            except AddressValueError:
                print("The excluded IPv4 \"{0}\" is not valid.".format(address))
                exit(ExitCode.BAD_EXCLUDED_IP)

    arg_output_dir = args.output_dir

    # Configure the scanner
    scanner_config: ScannerConfiguration = scanner_init(arg_target_network, arg_exclude_ips, arg_output_dir)
    Path(scanner_config.scan_output_dir).mkdir(parents=True, exist_ok=True)

    # Create the result object
    scanner_results: ScannerResults = ScannerResults()

    # Record the network traffic for two minutes
    print("Capturing the network trafic for two minutes...")
    perform_tcpdump(scanner_config.scan_output_dir)

    # Saving the host OS config
    print("Saving the DMESG")
    scanner_results.dmesg = read_dmesg()

    # Listing the online IPs
    print("Listing the online IPs")
    online_ips = check_online_ips(scanner_config.scan_target_network.network, scanner_config.scan_exclude_ips)

    # Perform the DNS scan
    print("Perform the DNS scan")
    scanner_results.dns_scan = dns_scan(online_ips.split(" "))

    # Perform the internet check
    print("Perform the internet access scan")
    scanner_results.internet_scan = internet_scan(scanner_results.dns_scan["proxy"])

    # Perform the Nmap scan
    print("Performing the Nmap scans (discovery + vulnerability)")
    print("Have a break, this will take a while.......")
    scanner_results.nmap_disco, scanner_results.nmap_vuln = nmap_scan(online_ips, True, output_dir=scanner_config.scan_output_dir)

    # Perform the website screenshots
    print("Perform the screenshot of found websites")
    perform_webcreenshot(scanner_results.nmap_disco, scanner_config.scan_output_dir)

    print("Generating the report")
    report: dict = create_report_dict(scanner_config, scanner_results)
    with open(scanner_config.scan_output_dir + "/report.json", 'w') as file:
        json.dump(report, file)

    print("Saving the results in a GPG archive")
    create_gpg_archive(scanner_config.scan_output_dir)
    input("Press enter to exit..........................")
    exit(0)
