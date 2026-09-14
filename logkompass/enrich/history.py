"""History lookups used by the rules that actually matter (R04 to R06).

Everything is scoped with a `before` timestamp so that today's own events cannot
make today's detection look normal. Re-running the rules gives the same answer.
"""

from __future__ import annotations

from typing import Protocol


class History(Protocol):
    def success_countries(self, before: str) -> set[str]: ...

    def known_fingerprints(self, before: str) -> set[str]: ...

    def country_of(self, ip: str) -> str | None: ...


class StoreHistory:
    def __init__(self, store, geo=None, known_fingerprints: list[str] | None = None) -> None:
        self.store = store
        self.geo = geo
        self.allowlist = set(known_fingerprints or [])

    def success_countries(self, before: str) -> set[str]:
        return self.store.accepted_countries_before(before)

    def known_fingerprints(self, before: str) -> set[str]:
        return self.store.key_fingerprints_before(before) | self.allowlist

    def country_of(self, ip: str) -> str | None:
        actor = self.store.actor(ip)
        if actor and actor.country:
            return actor.country
        if self.geo is not None:
            country, _asn, _org = self.geo(ip)
            return country
        return None


class StaticHistory:
    """Test double and the graceful degradation path when GeoIP is unavailable."""

    def __init__(
        self,
        countries: set[str] | None = None,
        fingerprints: set[str] | None = None,
        country_map: dict[str, str] | None = None,
    ) -> None:
        self._countries = countries or set()
        self._fingerprints = fingerprints or set()
        self._country_map = country_map or {}

    def success_countries(self, before: str) -> set[str]:
        return set(self._countries)

    def known_fingerprints(self, before: str) -> set[str]:
        return set(self._fingerprints)

    def country_of(self, ip: str) -> str | None:
        return self._country_map.get(ip)
