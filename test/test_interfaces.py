from unittest import TestCase
from ipaddress import IPv4Address, IPv4Network, IPv4Interface, IPv6Interface, IPv6Network
from scanner_lib.network_scanner.interfaces import *


class TestInterfaces(TestCase):
    def test_calculate_ipv4cidr(self):
        self.assertEqual(24, calculateIPv4CIDR("255.255.255.0"), "Test valid netmask")
        self.assertEqual(-1, calculateIPv4CIDR("255.255.255"), "Test invalid netmask format")
        self.assertEqual(-1, calculateIPv4CIDR("555.555.555.0"), "Test invalid netmask value")
        self.assertEqual(-1, calculateIPv4CIDR("hello"), "Test invalid input content")
        self.assertEqual(-1, calculateIPv4CIDR(None), "Test input is None")

    def test_calculate_ipv6cidr(self):
        self.assertEqual(64, calculateIPv6CIDR("ffff:ffff:ffff:ffff:0000:0000:0000:0000"), "Test valid netmask expanded")
        self.assertEqual(64, calculateIPv6CIDR("ffff:ffff:ffff:ffff::"), "Test valid netmask compressed")
        self.assertEqual(64, calculateIPv6CIDR("ffff:ffff:ffff:ffff::0000"), "Test valid netmask semi-compressed")
        self.assertEqual(-1, calculateIPv6CIDR("ffff:fZff:ffff:ffff:0000:0000:0000:0000"), "Test invalid netmask expanded")
        self.assertEqual(-1, calculateIPv6CIDR("ffff:ffff:ffff:GGGG::"), "Test invalid netmask compressed")
        self.assertEqual(-1, calculateIPv6CIDR("ffff:ffff:ffff:ffff::JJJJ"), "Test invalid netmask semi-compressed")
        self.assertEqual(-1, calculateIPv6CIDR("fac"), "Test invalid input content")
        self.assertEqual(-1, calculateIPv6CIDR(None), "Test input is None")

    def test_get_active_interfaces(self):
        ifs = get_active_interfaces()
        self.assertIsNotNone(get_active_interfaces(), "Test with a network interfaces")

    def test_get_ipv4_network(self):
        if_lo: Interface = Interface("lo")
        if_lo.mac = "7C:2C:8D:BE:BD:FB"
        if_lo.ipv4_interfaces = [IPv4Interface("127.0.0.0/24")]
        if_lo.ipv6_interfaces = [IPv6Interface("FE80::/10")]
        if_int: Interface = Interface("int")
        if_int.mac = "98:8D:18:49:0B:6E"
        if_int.ipv4_interfaces = [IPv4Interface("192.168.1.0/24")]
        if_int.ipv6_interfaces = [IPv6Interface("2001:0db8::/64")]

        self.assertEqual([IPv4Network("192.168.1.0/24")], get_ipv4_networks([if_lo, if_int]))
        self.assertEqual([], get_ipv4_networks([]))
        self.assertIsNotNone(get_ipv4_networks())

    def test_get_ipv4_address(self):
        if_int: Interface = Interface("int")
        if_int.mac = "98:8D:18:49:0B:6E"
        if_int.ipv4_interfaces = [IPv4Interface("192.168.1.5/24")]
        if_int.ipv6_interfaces = [IPv6Interface("2001:0db8::/64")]
        self.assertEqual([IPv4Address("192.168.1.5")], get_ipv4_address([if_int]))
        self.assertEqual([], get_ipv4_address([]))
        self.assertIsNotNone(get_ipv4_address())