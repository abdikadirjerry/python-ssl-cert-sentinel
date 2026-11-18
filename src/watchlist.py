from src.inspector import inspect_domain_tls

DEFAULT_WATCHLIST = [
    "github.com",
    "python.org",
    "cloudflare.com",
]


class DomainWatchlist:
    def __init__(self):
        self.domains = list(DEFAULT_WATCHLIST)

    def add(self, hostname: str) -> None:
        cleaned = hostname.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if cleaned and cleaned not in self.domains:
            self.domains.insert(0, cleaned)

    def remove(self, hostname: str) -> None:
        self.domains = [d for d in self.domains if d != hostname]

    def audit_all(self) -> list[dict]:
        return [inspect_domain_tls(domain) for domain in self.domains]