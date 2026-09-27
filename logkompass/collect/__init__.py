"""Collection entry point. Journald first, auth.log as the fallback."""

from __future__ import annotations

from ..config import Config
from ..store import GeoLookup, Store
from . import authlog, cowrie, journald


def collect_once(
    store: Store,
    cfg: Config,
    geo: GeoLookup | None = None,
    runner=None,
    reader=None,
) -> dict:
    """Pull new log lines, parse and store them. Idempotent, cursor based."""
    if cfg.collect.source == "journald":
        cursor = store.get_state("journal_cursor")
        batch = journald.read_journal(
            unit=cfg.collect.unit,
            cursor=cursor,
            max_lines=cfg.collect.max_lines_per_run,
            runner=runner,
            host=cfg.host,
        )
        result = store.insert_events(batch.events, geo=geo)
        if batch.cursor:
            store.set_state("journal_cursor", batch.cursor)
        source_detail = {"cursor": bool(batch.cursor)}
    elif cfg.collect.source == "cowrie":
        offset = int(store.get_state("cowrie_offset", "0") or 0)
        inode = store.get_state("cowrie_inode")
        batch = cowrie.read_cowrie(
            path=cfg.collect.cowrie_json_path,
            offset=offset,
            inode=int(inode) if inode else None,
            max_lines=cfg.collect.max_lines_per_run,
            host=cfg.host,
            reader=reader,
        )
        result = store.insert_events(batch.events, geo=geo)
        store.set_state("cowrie_offset", str(batch.offset))
        if batch.inode is not None:
            store.set_state("cowrie_inode", str(batch.inode))
        source_detail = {"offset": batch.offset, "rotated": batch.rotated}
    else:
        offset = int(store.get_state("authlog_offset", "0") or 0)
        inode = store.get_state("authlog_inode")
        batch = authlog.read_authlog(
            path=cfg.collect.authlog_path,
            offset=offset,
            inode=int(inode) if inode else None,
            max_lines=cfg.collect.max_lines_per_run,
            host=cfg.host,
            reader=reader,
        )
        result = store.insert_events(batch.events, geo=geo)
        store.set_state("authlog_offset", str(batch.offset))
        if batch.inode is not None:
            store.set_state("authlog_inode", str(batch.inode))
        source_detail = {"offset": batch.offset, "rotated": batch.rotated}

    return {
        "source": cfg.collect.source,
        "lines": result.seen,
        "inserted": result.inserted,
        "duplicates": result.duplicates,
        "skipped": batch.skipped,
        **source_detail,
    }
