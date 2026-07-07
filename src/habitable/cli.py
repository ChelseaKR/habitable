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
import hashlib
import json
import os
import sys
import webbrowser
from pathlib import Path

from cryptography import x509

from . import __version__
from .capture import capture, resolve_deferred, retimestamp_all
from .commons import DEFAULT_K, build_commons, summarize_case
from .config import TSAConfig
from .crypto import PublicIdentity
from .errors import HabitableError
from .i18n import cli_text, format_datetime, resolve_locale
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
    p_init.add_argument(
        "--building",
        default="",
        help="coarse building label for the opt-in aggregate commons (e.g. '1200 Elm')",
    )
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
    p_status.add_argument(
        "--xray",
        action="store_true",
        help="show a local, telemetry-free data-flow X-ray of what each component "
        "would expose externally (no network)",
    )
    p_status.set_defaults(func=_cmd_status)

    p_resolve = sub.add_parser("resolve", help="fetch timestamps for items queued offline")
    add_vault(p_resolve)
    p_resolve.add_argument("--dev-tsa", action="store_true")
    p_resolve.set_defaults(func=_cmd_resolve)

    p_retime = sub.add_parser(
        "retimestamp", help="archive-(re)timestamp items (survive cert aging)"
    )
    add_vault(p_retime)
    p_retime.add_argument("--dev-tsa", action="store_true")
    p_retime.set_defaults(func=_cmd_retimestamp)

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
    p_verify.add_argument(
        "--json",
        action="store_true",
        help="emit a structured JSON report (for scripts, integrators, and screen readers)",
    )
    p_verify.add_argument(
        "--trusted-cert",
        action="append",
        type=Path,
        metavar="PEM",
        help="a trusted RFC 3161 TSA root certificate (PEM); repeatable. Asserts each "
        "timestamp chains to a root you trust. Omit to verify token signatures without "
        "anchoring to a specific authority.",
    )
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
    p_relay.add_argument(
        "--persist-dir",
        type=Path,
        help="opt-in on-disk ciphertext journal (default: memory-only, nothing on disk)",
    )
    p_relay.set_defaults(func=_cmd_relay)

    p_app = sub.add_parser("app", help="run the local web app (accessible, EN/ES)")
    add_vault(p_app)
    p_app.add_argument("--host", default="127.0.0.1")
    p_app.add_argument("--port", type=int, default=8765)
    p_app.add_argument("--dev-tsa", action="store_true", help="use the offline dev TSA")
    p_app.add_argument("--no-timestamp", action="store_true", help="defer timestamping")
    p_app.add_argument("--no-browser", action="store_true", help="do not open a browser")
    p_app.set_defaults(func=_cmd_app)

    p_key = sub.add_parser("key", help="manage vault keys: rotate, backup, restore, share, recover")
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
    p_key_share = key_sub.add_parser(
        "share",
        help="split recovery so any M of N stewards can recover (threshold social custody)",
    )
    add_vault(p_key_share)
    p_key_share.add_argument(
        "--threshold", "-m", required=True, type=int, help="how many stewards must cooperate (M)"
    )
    p_key_share.add_argument(
        "--steward",
        action="append",
        default=[],
        metavar="NAME",
        help="name/label for a steward who holds one share (repeat for each of the N)",
    )
    p_key_share.add_argument(
        "--out-dir", required=True, type=Path, help="directory to write the bundle and shares"
    )
    p_key_share.set_defaults(func=_cmd_key_share)
    p_key_recover = key_sub.add_parser(
        "recover", help="rebuild a vault keyfile from a recovery bundle and a quorum of shares"
    )
    p_key_recover.add_argument("vault", type=Path)
    p_key_recover.add_argument(
        "--bundle", required=True, type=Path, help="the recovery bundle file (from key share)"
    )
    p_key_recover.add_argument(
        "--share",
        action="append",
        default=[],
        metavar="FILE",
        dest="shares",
        help="a steward's share file (repeat; you need at least M of them)",
    )
    p_key_recover.add_argument("--new-passphrase", help="new vault passphrase (else prompt)")
    p_key_recover.set_defaults(func=_cmd_key_recover)

    p_commons = sub.add_parser(
        "commons",
        help="opt-in: compute a k-anonymous aggregate summary across cases (no telemetry)",
    )
    p_commons.add_argument(
        "--vault",
        dest="vaults",
        required=True,
        action="append",
        type=Path,
        metavar="VAULT",
        help="a case vault to include; repeat --vault for each case in the union",
    )
    p_commons.add_argument(
        "--out",
        required=True,
        type=Path,
        help="file to write the aggregate summary to (nothing is sent anywhere)",
    )
    p_commons.add_argument(
        "--k",
        type=int,
        default=DEFAULT_K,
        help=f"k-anonymity threshold: suppress cells under k households (default {DEFAULT_K})",
    )
    p_commons.add_argument(
        "--period",
        choices=("month", "quarter"),
        default="month",
        help="time-bucket granularity for the summary (default month)",
    )
    p_commons.add_argument(
        "--passphrase",
        help="shared vault passphrase (else HABITABLE_PASSPHRASE, else prompted per vault)",
    )
    p_commons.set_defaults(func=_cmd_commons)

    p_demo = sub.add_parser("demo", help="walk a synthetic case end to end (no real data)")
    p_demo.set_defaults(func=_cmd_demo)

    p_prove = sub.add_parser(
        "prove-no-plaintext",
        help="prove no plaintext reaches the relay: real sync + wire capture + marker grep",
    )
    p_prove.add_argument(
        "--capture-dir",
        type=Path,
        help="directory to write the wire-capture file to (default: a temp dir)",
    )
    p_prove.set_defaults(func=_cmd_prove)

    return parser


# --- commands -----------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    passphrase = _passphrase(args, confirm=True)
    vault = Vault.create(
        args.vault,
        passphrase,
        case_id=args.case,
        unit=args.unit,
        building=args.building,
        language=args.lang,
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
    extra_tsas = [] if args.no_timestamp else _extra_tsas_for(vault, dev=args.dev_tsa)
    result = capture(vault, args.media, issue_id=args.issue, tsa=tsa, extra_tsas=extra_tsas)
    locale = resolve_locale(vault.config.language)
    status = (
        cli_text(
            "capture_timestamped",
            locale,
            when=format_datetime(result.timestamp_info.gen_time, locale),
        )
        if result.timestamped and result.timestamp_info
        else cli_text("capture_awaiting", locale)
    )
    print(f"habitable: captured {result.capture_id}")
    print(f"           content hash {result.content_hash[:16]}… · {status}")
    if result.extra_authorities:
        also = cli_text(
            "capture_also_timestamped",
            locale,
            count=len(result.extra_authorities),
            names=", ".join(result.extra_authorities),
        )
        print(f"           {also}")
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
    if getattr(args, "xray", False):
        from .prove import data_flow_xray

        print(data_flow_xray(vault))
        return 0
    locale = resolve_locale(vault.config.language)
    unit = vault.document.get_meta("unit") or vault.document.case_id
    issues = vault.document.issues()
    captures = vault.document.captures()
    timeline = vault.document.timeline()
    summary = cli_text(
        "status_summary",
        locale,
        unit=unit,
        issues=len(issues),
        captures=len(captures),
        timeline=len(timeline),
    )
    print(f"habitable: {summary}")
    for issue in issues:
        n = len(vault.document.captures(issue.issue_id))
        line = cli_text(
            "status_issue_line",
            locale,
            issue_id=issue.issue_id,
            title=issue.title or issue.category,
            status=issue.status,
            captures=n,
        )
        print(f"  · {line}")
    timestamped = sum(1 for c in captures if vault.get_token(c.capture_id) is not None)
    stamps = cli_text(
        "status_timestamps",
        locale,
        timestamped=timestamped,
        total=len(captures),
        awaiting=len(vault.deferred()),
    )
    print(f"  {stamps}")
    custody = vault.custody.verify()
    verdict = cli_text("custody_intact" if custody.ok else "custody_broken", locale)
    print(f"  {cli_text('status_custody', locale, verdict=verdict, links=custody.length)}")
    return 0


def _cmd_resolve(args: argparse.Namespace) -> int:
    vault = _open(args)
    tsa = _tsa_for(vault, dev=args.dev_tsa)
    if tsa is None:
        raise HabitableError("no timestamp authority configured")
    results = resolve_deferred(vault, tsa, extra_tsas=_extra_tsas_for(vault, dev=args.dev_tsa))
    locale = resolve_locale(vault.config.language)
    print(f"habitable: {cli_text('resolve_done', locale, count=len(results))}")
    return 0


def _cmd_retimestamp(args: argparse.Namespace) -> int:
    vault = _open(args)
    tsa = _tsa_for(vault, dev=args.dev_tsa)
    if tsa is None:
        raise HabitableError("no timestamp authority configured")
    count = retimestamp_all(vault, tsa, extra_tsas=_extra_tsas_for(vault, dev=args.dev_tsa))
    locale = resolve_locale(vault.config.language)
    print(f"habitable: {cli_text('retimestamp_done', locale, count=count)}")
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
    locale = resolve_locale(vault.config.language)
    unit = vault.document.get_meta("unit") or vault.document.case_id
    issues = vault.document.issues() if args.issue is None else [args.issue]
    timeline = len(vault.document.timeline())
    summary = cli_text(
        "status_summary",
        locale,
        unit=unit,
        issues=len(issues),
        captures=result.item_count,
        timeline=timeline,
    )
    print(f"habitable: {summary}")
    stamped = cli_text(
        "export_timestamped_line",
        locale,
        timestamped=result.timestamped_count,
        total=result.item_count,
    )
    print(f"           {stamped}")
    awaiting = result.item_count - result.timestamped_count
    if awaiting > 0:
        # An awaiting-timestamp packet reports NOT intact under `habitable verify` —
        # correct, degraded behavior. Say so at export time, with the next step,
        # rather than letting a recipient's verify run be the first notice (FIX-09).
        hint = cli_text("export_awaiting_hint", locale, awaiting=awaiting)
        print(f"           {hint}")
    for note in result.disclosures:
        print(f"           {note}")
    print(f"           packet written to {result.out_dir}")
    return 0


def _load_trusted_certs(paths: list[Path] | None) -> list[x509.Certificate] | None:
    if not paths:
        return None
    certs: list[x509.Certificate] = []
    for path in paths:
        try:
            certs.append(x509.load_pem_x509_certificate(path.read_bytes()))
        except (OSError, ValueError) as exc:
            raise HabitableError(f"could not load trusted certificate {path}: {exc}") from exc
    return certs


def _cmd_verify(args: argparse.Namespace) -> int:
    report = verify_packet(args.packet, trusted_certs=_load_trusted_certs(args.trusted_cert))
    if args.json:
        payload = {
            "ok": report.ok,
            "summary": report.summary(),
            "signature_ok": report.signature_ok,
            "custody_ok": report.custody_ok,
            "custody_length": report.custody_length,
            "verified_items": report.verified_items,
            "item_count": len(report.items),
            "problems": list(report.problems),
            "items": [
                {
                    "capture_id": item.capture_id,
                    "content_hash": item.content_hash,
                    "ok": item.ok,
                    "timestamp_verified": item.timestamp_verified,
                    "gen_time": item.gen_time,
                    "tsa_name": item.tsa_name,
                    "shared_media_ok": item.shared_media_ok,
                    "custody_binding_ok": item.custody_binding_ok,
                    "original_fixity_ok": item.original_fixity_ok,
                    "verified_authorities": list(item.verified_authorities),
                    "notes": list(item.notes),
                }
                for item in report.items
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if report.ok else 1
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
    locale = resolve_locale(vault.config.language)
    done = cli_text(
        "sync_done",
        locale,
        messages=result.messages_merged,
        captures=result.captures_imported,
    )
    print(f"habitable: {done}")
    return 0


def _cmd_relay(args: argparse.Namespace) -> int:
    from .relay import serve

    serve(args.host, args.port, persist_dir=args.persist_dir)
    return 0


def _cmd_app(args: argparse.Namespace) -> int:
    from .appserver import make_app_server

    vault = _open(args)
    tsa = None if args.no_timestamp else _tsa_for(vault, dev=args.dev_tsa)
    extra_tsas = [] if args.no_timestamp else _extra_tsas_for(vault, dev=args.dev_tsa)
    server = make_app_server(args.host, args.port, vault, tsa=tsa, extra_tsas=extra_tsas)
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


def _cmd_commons(args: argparse.Namespace) -> int:
    contributions = []
    for vault_path in args.vaults:
        vault = Vault.open(vault_path, _passphrase(args))
        case_id = vault.document.case_id
        # An opaque, non-emitted handle used only to count distinct households
        # when applying the k-anonymity threshold. Never written to the export.
        household_token = hashlib.sha256(f"commons-household::{case_id}".encode()).hexdigest()
        building_label = vault.document.get_meta("building") or case_id
        contributions.append(
            summarize_case(
                vault.document,
                building_label=building_label,
                household_token=household_token,
                granularity=args.period,
            )
        )
    export = build_commons(contributions, k=args.k, granularity=args.period)
    args.out.write_text(
        json.dumps(export.to_json(), indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"habitable: wrote k-anonymous commons summary to {args.out} "
        f"(k={export.k}, {len(export.cells)} cell(s) published, "
        f"{export.suppressed_cells} suppressed, "
        f"{export.contributing_cases} case(s) contributing)"
    )
    print(
        "           nothing was transmitted; publishing this file is a separate, "
        "deliberate act you control."
    )
    return 0


def _cmd_key_share(args: argparse.Namespace) -> int:
    vault = _open(args)
    stewards: list[str] = list(args.steward)
    if not stewards:
        raise HabitableError("give a --steward NAME for each share (at least two)")
    if args.threshold < 2 or args.threshold > len(stewards):
        raise HabitableError(
            f"--threshold M must satisfy 2 <= M <= number of stewards "
            f"(M={args.threshold}, N={len(stewards)})"
        )
    bundle, shares = vault.export_social_shares(args.threshold, stewards)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / "recovery-bundle.json"
    bundle_path.write_text(bundle, encoding="utf-8")
    share_paths: list[Path] = []
    for i, (steward, share) in enumerate(zip(stewards, shares, strict=True), start=1):
        share_path = out_dir / f"share-{i:02d}-{_slug(steward)}.json"
        share_path.write_text(share, encoding="utf-8")
        share_paths.append(share_path)

    print(
        f"habitable: split recovery into {len(shares)} shares; "
        f"any {args.threshold} can recover together."
    )
    print(f"           bundle:  {bundle_path}")
    for steward, share_path in zip(stewards, share_paths, strict=True):
        print(f"           share:   {share_path}  →  give to {steward}")
    print("           Hand each share to a DIFFERENT steward and keep them apart.")
    print(f"           No single steward can recover; any {args.threshold} together can.")
    print("           The bundle is not secret, but is useless without a quorum of shares.")
    return 0


def _cmd_key_recover(args: argparse.Namespace) -> int:
    if len(args.shares) < 2:
        raise HabitableError("pass at least two --share FILE values (a quorum of stewards)")
    new = _new_passphrase(args.new_passphrase)
    bundle = args.bundle.read_text(encoding="utf-8")
    share_blobs = [Path(p).read_text(encoding="utf-8") for p in args.shares]
    Vault.restore_from_shares(args.vault, bundle, share_blobs, new)
    print(f"habitable: keyfile restored for {args.vault}; open it with the new passphrase.")
    return 0


def _slug(name: str) -> str:
    cleaned = "".join(c if c.isalnum() else "-" for c in name.strip().lower())
    return "-".join(filter(None, cleaned.split("-"))) or "steward"


def _cmd_demo(_args: argparse.Namespace) -> int:
    from .demo import run_demo

    return run_demo()


def _cmd_prove(args: argparse.Namespace) -> int:
    from .prove import format_report, prove_no_plaintext

    report = prove_no_plaintext(args.capture_dir)
    print(format_report(report))
    return report.exit_code


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


def _extra_tsas_for(vault: Vault, *, dev: bool) -> list[TimestampAuthority]:
    """Every configured authority beyond the primary, for redundant stamping (R-16)."""
    if dev:
        return []
    return [_build_authority(t) for t in vault.config.timestamp_authorities[1:]]


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
