from unittest import TestCase
from scanner_lib.network_scanner.web_exposure import *


class TestWebExposure(TestCase):
    def test_bulk_ping(self):
        self.assertEqual(["127.0.0.1", "10.210.114.166"], bulk_ping(["127.0.0.1", "10.210.114.166", "8.8.8.8"]), "Test with known IP")
        self.assertIsNone(bulk_ping(None), "Test without str array, None value")

    def test_get_host_nameserver(self):
        self.assertIsNotNone(get_host_nameservers())

    def test_host_search_domains(self):
        self.assertIsNotNone(get_host_search_domains())

    def test_dns_lookup(self):
        self.assertIsNotNone(dns_lookup("www.example.com"), "Test dns lookup www.example.com")
        self.assertIsNotNone(dns_lookup("www.myfakedomain.net"))
        self.assertIsNone(dns_lookup(""))

    def test_dns_lookup_bulk(self):
        self.assertIsNotNone(dns_lookup_bulk(["www.myfakedomain.net", "www.example.com"]))
        self.assertIsNone(dns_lookup_bulk([]))
        self.assertIsNone(dns_lookup_bulk(None))

    def test_reverse_dns_lookup(self):
        self.assertEqual(('1.0.0.127.in-addr.arpa.', 'localhost.'), reverse_dns_lookup("127.0.0.1"))
        self.assertEqual(('2.121.210.10.in-addr.arpa.', ''), reverse_dns_lookup("10.210.121.2"))
        self.assertEqual(('7.43.0.192.in-addr.arpa.', 'icann.org.'), reverse_dns_lookup("192.0.43.7"))
        self.assertIsNone(reverse_dns_lookup(""))

    def test_reverse_dns_lookup_bulk(self):
        self.assertIsNotNone(reverse_dns_lookup_bulk(["192.0.43.7", "127.0.0.1"]))
        self.assertIsNone(reverse_dns_lookup_bulk([]))
        self.assertIsNone(reverse_dns_lookup_bulk(None))

    def test_open_connection(self):
        self.assertTrue(open_connection("localhost", 22))
        self.assertFalse(open_connection("localhost", 21))
        self.assertFalse(open_connection("localhost", 0))

    def test_get_accessible_service(self):
        self.assertIsNotNone(get_accessible_service(["8.8.8.8", "9.9.9.9", "1.1.1.1"], 53))
        self.assertIsNone(get_accessible_service(["localhost"], 0))
        self.assertIsNone(get_accessible_service([], 22))
        self.assertIsNone(get_accessible_service(None, 22))
        self.assertIsNone(get_accessible_service("127.0.0.1", 0))
