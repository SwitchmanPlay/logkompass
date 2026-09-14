"""GeoLite2 country and ASN lookups.

Local mmdb files only: no per-lookup API, no rate limit, works offline and keeps the
tests hermetic. Readers are injected so tests never touch a real database.
"""

from __future__ import annotations

from pathlib import Path


class GeoIp:
    def __init__(self, country_reader=None, asn_reader=None) -> None:
        self.country_reader = country_reader
        self.asn_reader = asn_reader

    @classmethod
    def from_paths(cls, country_path: str | None, asn_path: str | None) -> "GeoIp":
        country_reader = asn_reader = None
        try:
            import geoip2.database  # type: ignore
        except ImportError:
            return cls()
        if country_path and Path(country_path).is_file():
            country_reader = geoip2.database.Reader(country_path)
        if asn_path and Path(asn_path).is_file():
            asn_reader = geoip2.database.Reader(asn_path)
        return cls(country_reader, asn_reader)

    @property
    def enabled(self) -> bool:
        return bool(self.country_reader or self.asn_reader)

    def lookup(self, ip: str) -> tuple[str | None, int | None, str | None]:
        country = asn = as_org = None
        if self.country_reader is not None:
            try:
                country = self.country_reader.country(ip).country.iso_code
            except Exception:  # noqa: BLE001 - unknown IP is normal, not an error
                country = None
        if self.asn_reader is not None:
            try:
                response = self.asn_reader.asn(ip)
                asn = response.autonomous_system_number
                as_org = response.autonomous_system_organization
            except Exception:  # noqa: BLE001
                asn = as_org = None
        return country, asn, as_org

    def __call__(self, ip: str) -> tuple[str | None, int | None, str | None]:
        return self.lookup(ip)

    def close(self) -> None:
        for reader in (self.country_reader, self.asn_reader):
            if reader is not None and hasattr(reader, "close"):
                reader.close()
