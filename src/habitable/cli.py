# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The ``habitable`` command-line interface.

A few-taps-equivalent for the terminal: initialize a case, capture evidence,
keep a timeline, sync with an organizer, export a packet, and verify one. No
account, nothing to sign up for under stress. ``habitable demo`` walks the whole
flow on synthetic data with no network and no real tenant information.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .capture import capture, resolve_deferred
from .config import TSAConfig
from .crypto import PublicIdentity
from .errors import HabitableError
from .packet import build_packet
from .sync import LocalDirTransport, RelayClient, Transport, sync
from .tsa import DevTSA, Rfc3161HttpTSA, TimestampAuthority
from .vault import Vault
from .verify import verify_packet

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        result: int = args.func(args)
    except HabitableError as exc:
        print(f"habitable: error: {exc}", file=sys.stderr)
        return 1
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="habitable", description=__doc__)
    parser.add_argument("--version", action="version", version=f"habitable {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_vault(p: argparse.ArgumentParser) -> None:
        p.add_argument("--vault", required=True, type=Path, help="path to the case vault")
        p.add_argument(
            "--passphrase", help="vault passphrase (else HABITABLE_PASSPHRASE or prompt)"
        )

    p_init = sub.add_parser("init", help="create a new encrypted case vault")
    p_init.add_argument("vault", type=Path)
    p_init.add_argument("--case", required=True, help="case id, e.g. a building or unit code")
    p_init.add_argument("--unit", default="", help="unit label, e.g. 4B")
    p_init.add_argument("--lang", default="en")
    p_init.add_argument("--passphrase")
    p_init.set_defaults(func=_cmd_init)

    p_id = sub.add_parser("id", help="print this device's public identity (share with peers)")
    add_vault(p_id)
    p_id.set_defaults(func=_cmd_id)

    p_issue = sub.add_parser("issue", help="add an issue to the case")
    add_vault(p_issue)
    p_issue.add_argument("--category", required=True)
    p_issue.add_argument("--room", default="")
    p_issue.add_argument("--title", default="")
    p_issue.add_argument("--severity", default="")
    p_issue.add_argument("--description", default="")
    p_issue.set_defaults(func=_cmd_issue)

    p_capture = sub.add_parser("capture", help="capture a media file as evidence")
    add_vault(p_capture)
    p_capture.add_argument("media", type=Path)
    p_capture.add_argument("--issue", required=True)
    p_capture.add_argument("--dev-tsa", action="store_true", help="use the offline dev TSA")
    p_capture.add_argument("--no-timestamp", action="store_true", help="defer timestamping")
    p_capture.set_defaults(func=_cmd_capture)

    p_tl = sub.add_parser("timeline", help="add a timeline entry")
    add_vault(p_tl)
    p_tl.add_argument("--issue", required=True)
    p_tl.add_argument("--kind", required=True, help="e.g. observed, sent_request, inspection")
    p_tl.add_argument("--text", required=True)
    p_tl.set_defaults(func=_cmd_timeline)

    p_status = sub.add_parser("status", help="show the state of the case")
    add_vault(p_status)
    p_status.set_defaults(func=_cmd_status)

    p_resolve = sub.add_parser("resolve", help="fetch timestamps for items queued offline")
    add_vault(p_resolve)
    p_resolve.add_argument("--dev-tsa", action="store_true")
    p_resolve.set_defaults(func=_cmd_resolve)

    p_export = sub.add_parser("export", help="assemble a court/inspector evidence packet")
    add_vault(p_export)
    p_export.add_argument("--out", required=True, type=Path, help="output packet directory")
    p_export.add_argument("--issue", help="export one issue (default: the whole unit)")
    p_export.add_argument("--since", help="only items captured on/after this ISO date")
    p_export.add_argument("--include-originals", action="store_true")
    p_export.add_argument("--no-pdf", action="store_true")
    p_export.set_defaults(func=_cmd_export)

    p_verify = sub.add_parser("verify", help="independently verify a packet")
    p_verify.add_argument("packet", type=Path)
    p_verify.set_defaults(func=_cmd_verify)

    p_sync = sub.add_parser("sync", help="sync the case with a peer")
    add_vault(p_sync)
    p_sync.add_argument("--peer", required=True, help="peer public identity (from `habitable id`)")
    p_sync.add_argument("--channel", required=True, help="shared room/channel id")
    p_sync.add_argument("--relay", help="relay base URL (https://...)")
    p_sync.add_argument("--dir", type=Path, help="shared directory transport")
    p_sync.set_defaults(func=_cmd_sync)

    p_relay = sub.add_parser("relay", help="run an optional ciphertext-only sync relay")
    p_relay.add_argument("--host", default="127.0.0.1")
    p_relay.add_argument("--port", type=int, default=8787)
    p_relay.set_defaults(func=_cmd_relay)

    p_app = sub.add_parser("app", help="run the local web app (accessible, EN/ES)")
    add_vault(p_app)
    p_app.add_argument("--host", default="127.0.0.1")
    p_app.add_argument("--port", type=int, default=8765)
    p_app.add_argument("--dev-tsa", action="store_true", help="use the offline dev TSA")
    p_app.add_argument("--no-timestamp", action="store_true", help="defer timestamping")
    p_app.add_argument("--no-browser", action="store_true", help="do not open a browser")
    p_app.set_defaults(func=_cmd_app)

    p_key = sub.add_parser("key", help="manage vault keys: rotate, backup, restore")
    key_sub = p_key.add_subparsers(dest="key_action")
    p_key_rotate = key_sub.add_parser("rotate", help="change the vault passphrase")
    add_vault(p_key_rotate)
    p_key_rotate.add_argument("--new-passphrase", help="new passphrase (else prompt)")
    p_key_rotate.set_defaults(func=_cmd_key_rotate)
    p_key_backup = key_sub.add_parser(
        "backup", help="write an encrypted recovery backup of the key"
    )
    add_vault(p_key_backup)
    p_key_backup.add_argument("--out", required=True, type=Path, help="recovery file to write")
    p_key_backup.add_argument(
        "--recovery-passphrase", help="passphrase for the backup (else prompt)"
    )
    p_key_backup.set_defaults(func=_cmd_key_backup)
    p_key_restore = key_sub.add_parser(
        "restore", help="rebuild a vault keyfile from a recovery backup"
    )
    p_key_restore.add_argument("vault", type=Path)
    p_key_restore.add_argument("--recovery-file", required=True, type=Path)
    p_key_restore.add_argument("--recovery-passphrase", help="backup passphrase (else prompt)")
    p_key_restore.add_argument("--new-passphrase", help="new vault passphrase (else prompt)")
    p_key_restore.set_defaults(func=_cmd_key_restore)

    p_demo = sub.add_parser("demo", help="walk a synthetic case end to end (no real data)")
    p_demo.set_defaults(func=_cmd_demo)

    return parser


# --- commands -----------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    passphrase = _passphrase(args, confirm=True)
    vault = Vault.create(
        args.vault, passphrase, case_id=args.case, unit=args.unit, language=args.lang
    )
    print(f"habitable: created vault at {vault.path} for case {args.case!r}")
    print(f"           device fingerprint: {vault.identity.public().fingerprint}")
    return 0


def _cmd_id(args: argparse.Namespace) -> int:
    vault = _open(args)
    public = vault.identity.public()
    print(f"fingerprint: {public.fingerprint}")
    print(f"public-id:   {public.encode()}")
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    vault = _open(args)
    issue_id = vault.document.add_issue(
        category=args.category,
        room=args.room,
        title=args.title,
        severity=args.severity,
        description=args.description,
    )
    vault.save()
    print(f"habitable: added issue {issue_id} ({args.category})")
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    vault = _open(args)
    tsa = None if args.no_timestamp else _tsa_for(vault, dev=args.dev_tsa)
    result = capture(vault, args.media, issue_id=args.issue, tsa=tsa)
    status = (
        f"timestamped ({result.timestamp_info.gen_time})"
        if result.timestamped and result.timestamp_info
        else "awaiting timestamp (queued)"
    )
    print(f"habitable: captured {result.capture_id}")
    print(f"           content hash {result.content_hash[:16]}… · {status}")
    if result.had_location:
        print("           note: original retains location; shared copies will strip it")
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    vault = _open(args)
    entry_id = vault.document.add_timeline_entry(args.issue, args.kind, args.text)
    vault.save()
    print(f"habitable: added timeline entry {entry_id} ({args.kind})")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    vault = _open(args)
    unit = vault.document.get_meta("unit") or vault.document.case_id
    issues = vault.document.issues()
    captures = vault.document.captures()
    timeline = vault.document.timeline()
    print(
        f"habitable: unit {unit} — {len(issues)} issue(s), {len(captures)} capture(s), "
        f"{len(timeline)} timeline entr{'y' if len(timeline) == 1 else 'ies'}"
    )
    for issue in issues:
        n = len(vault.document.captures(issue.issue_id))
        print(
            f"  · {issue.issue_id}: {issue.title or issue.category} "
            f"[{issue.status}] — {n} capture(s)"
        )
    timestamped = sum(1 for c in captures if vault.get_token(c.capture_id) is not None)
    print(f"  timestamps: {timestamped}/{len(captures)} present; {len(vault.deferred())} awaiting")
    custody = vault.custody.verify()
    print(f"  chain of custody: {'intact' if custody.ok else 'BROKEN'} ({custody.length} entries)")
    return 0


def _cmd_resolve(args: argparse.Namespace) -> int:
    vault = _open(args)
    tsa = _tsa_for(vault, dev=args.dev_tsa)
    if tsa is None:
        raise HabitableError("no timestamp authority configured")
    results = resolve_deferred(vault, tsa)
    print(f"habitable: timestamped {len(results)} previously-queued item(s)")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    vault = _open(args)
    result = build_packet(
        vault,
        args.out,
        issue_id=args.issue,
        since=args.since,
        include_originals=args.include_originals,
        make_pdf=not args.no_pdf,
    )
    unit = vault.document.get_meta("unit") or vault.document.case_id
    issues = vault.document.issues() if args.issue is None else [args.issue]
    timeline = len(vault.document.timeline())
    print(
        f"habitable: unit {unit} — {len(issues)} issue(s), {result.item_count} capture(s), "
        f"{timeline} timeline entr{'y' if timeline == 1 else 'ies'}"
    )
    print(
        f"           {result.timestamped_count}/{result.item_count} media items: "
        f"content hash present, trusted timestamp attached"
    )
    for note in result.disclosures:
        print(f"           {note}")
    print(f"           packet written to {result.out_dir}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    report = verify_packet(args.packet)
    print(f"habitable: {report.summary()}")
    if not report.ok:
        for item in report.items:
            if not item.ok:
                detail = "; ".join(item.notes) or "failed"
                print(f"  · {item.capture_id}: {detail}", file=sys.stderr)
        return 1
    return 0


def _cmd_sync(args: argparse.Namespace) -> int:
    vault = _open(args)
    peer = PublicIdentity.decode(args.peer)
    transport = _transport(args)
    result = sync(vault, peer, transport, channel=args.channel)
    print(
        f"habitable: synced — merged {result.messages_merged} message(s), "
        f"imported {result.captures_imported} capture(s)"
    )
    return 0


def _cmd_relay(args: argparse.Namespace) -> int:
    from .relay import serve

    serve(args.host, args.port)
    return 0


def _cmd_app(args: argparse.Namespace) -> int:
    from .appserver import make_app_server

    vault = _open(args)
    tsa = None if args.no_timestamp else _tsa_for(vault, dev=args.dev_tsa)
    server = make_app_server(args.host, args.port, vault, tsa=tsa)
    url = f"http://{args.host}:{args.port}"
    print(f"habitable: local app running at {url}  (Ctrl-C to stop)")
    print("           loopback only — your case stays on this device.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
    return 0


def _cmd_key_rotate(args: argparse.Namespace) -> int:
    vault = _open(args)  # validates the current passphrase
    new = _new_passphrase(args.new_passphrase)
    vault.rotate_passphrase(new)
    print("habitable: vault passphrase rotated. Update any recovery backups accordingly.")
    return 0


def _cmd_key_backup(args: argparse.Namespace) -> int:
    vault = _open(args)
    recovery = _new_passphrase(args.recovery_passphrase, label="Recovery passphrase: ")
    args.out.write_text(vault.export_recovery(recovery), encoding="utf-8")
    print(f"habitable: recovery backup written to {args.out}")
    print("           keep it AND its passphrase safe and separate; without a backup,")
    print("           a lost passphrase means the data is unrecoverable (by design).")
    return 0


def _cmd_key_restore(args: argparse.Namespace) -> int:
    recovery = args.recovery_passphrase or getpass.getpass("Recovery passphrase: ")
    new = _new_passphrase(args.new_passphrase)
    blob = args.recovery_file.read_text(encoding="utf-8")
    Vault.restore_keyfile(args.vault, blob, recovery, new)
    print(f"habitable: keyfile restored for {args.vault}; open it with the new passphrase.")
    return 0


def _cmd_demo(_args: argparse.Namespace) -> int:
    from .demo import run_demo

    return run_demo()


# --- helpers ------------------------------------------------------------------


def _open(args: argparse.Namespace) -> Vault:
    return Vault.open(args.vault, _passphrase(args))


def _passphrase(args: argparse.Namespace, *, confirm: bool = False) -> str:
    if getattr(args, "passphrase", None):
        return str(args.passphrase)
    env = os.environ.get("HABITABLE_PASSPHRASE")
    if env:
        return env
    passphrase = getpass.getpass("Vault passphrase: ")
    if confirm and passphrase != getpass.getpass("Confirm passphrase: "):
        raise HabitableError("passphrases did not match")
    return passphrase


def _new_passphrase(value: str | None, *, label: str = "New passphrase: ") -> str:
    """A passphrase from a flag, or prompted twice for confirmation."""
    if value:
        return value
    chosen = getpass.getpass(label)
    if chosen != getpass.getpass("Confirm: "):
        raise HabitableError("passphrases did not match")
    return chosen


def _tsa_for(vault: Vault, *, dev: bool) -> TimestampAuthority | None:
    if dev:
        return DevTSA("dev-tsa")
    authorities = vault.config.timestamp_authorities
    return _build_authority(authorities[0]) if authorities else None


def _build_authority(config: TSAConfig) -> TimestampAuthority:
    if config.kind == "dev":
        return DevTSA(config.name)
    return Rfc3161HttpTSA(config.name, config.url)


def _transport(args: argparse.Namespace) -> Transport:
    if args.relay:
        return RelayClient(args.relay)
    if args.dir:
        return LocalDirTransport(args.dir)
    raise HabitableError("sync needs a transport: pass --relay URL or --dir PATH")
