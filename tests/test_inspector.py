import unittest
from src.inspector import inspect_domain_tls
from src.watchlist import DomainWatchlist


class TestCertSentinel(unittest.TestCase):
    def test_empty_hostname_returns_error(self):
        result = inspect_domain_tls("   ")
        self.assertFalse(result["ok"])
        self.assertIn("valid domain", result["error"].lower())

    def test_watchlist_normalizes_and_deduplicates_domains(self):
        wl = DomainWatchlist()
        wl.add("https://Example.COM/path")
        wl.add("example.com")
        self.assertEqual(wl.domains.count("example.com"), 1)
        self.assertEqual(wl.domains[0], "example.com")


if __name__ == "__main__":
    unittest.main()