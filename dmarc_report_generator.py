#!/usr/bin/env python3
import argparse
import gzip
import io
import os
import random
import smtplib
import ssl
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import xml.etree.ElementTree as ET
import ipaddress
from typing import List, Tuple, Set

import dns.resolver  # NEW

# ------------------------
# SPF include resolution
# ------------------------

def _txt_records(name: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=5.0)
        out = []
        for rr in ans:
            # rr.strings is deprecated; rr is <dns.rdataset..>; use .to_text()
            t = rr.to_text()
            # Remove surrounding quotes and join split TXT
            if t.startswith('"') and t.endswith('"'):
                t = t[1:-1]
            out.append(t.replace('\"', '"'))
        return out
    except Exception:
        return []

def _parse_spf_line(line: str):
    # Return tuple: (list of ip networks, list of nested includes)
    nets: List[ipaddress._BaseNetwork] = []
    includes: List[str] = []
    if not line.lower().startswith("v=spf1"):
        return nets, includes
    parts = line.split()
    for p in parts[1:]:
        try:
            if p.startswith("ip4:"):
                nets.append(ipaddress.ip_network(p[4:], strict=False))
            elif p.startswith("ip6:"):
                nets.append(ipaddress.ip_network(p[4:], strict=False))
            elif p.startswith("include:"):
                includes.append(p[8:])
            # (Optional) a/aaaa mechanisms could be expanded here if needed
        except Exception:
            continue
    return nets, includes

def resolve_spf_includes(includes: List[str], max_depth: int = 4) -> Tuple[List[ipaddress._BaseNetwork], Set[str]]:
    """
    Resolve a list of SPF include domains into a list of ip networks.
    Returns (networks, visited_domains).
    """
    nets: List[ipaddress._BaseNetwork] = []
    visited: Set[str] = set()
    stack = [(inc.strip(), 0) for inc in includes if inc.strip()]
    while stack:
        dom, depth = stack.pop()
        if not dom or dom in visited or depth > max_depth:
            continue
        visited.add(dom)
        for txt in _txt_records(dom):
            spf_nets, nested = _parse_spf_line(txt)
            nets.extend(spf_nets)
            for inc in nested:
                if inc not in visited:
                    stack.append((inc, depth + 1))
    return nets, visited

def pick_ip_from_networks(nets: List[ipaddress._BaseNetwork]) -> str:
    if not nets:
        # Fallback random IPv4
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    net = random.choice(nets)
    # Choose a random host within network (avoid network/broadcast on v4)
    if isinstance(net, ipaddress.IPv4Network):
        size = net.num_addresses
        if size <= 2:
            return str(net.network_address)
        # random host index from 1 .. size-2
        idx = random.randint(1, size - 2)
        return str(net.network_address + idx)
    else:
        # IPv6: pick from range; avoid first address to keep variety
        size = net.num_addresses
        offset = random.randint(1, min(size - 1, 2**32))  # cap to keep math quick
        return str(net.network_address + offset)

# ------------------------
# DMARC XML generation
# ------------------------
def generate_dmarc_xml(
    org_name: str,
    report_domain: str,
    begin_ts: int,
    end_ts: int,
    pass_nets: List[ipaddress._BaseNetwork],
    fail_nets: List[ipaddress._BaseNetwork],
) -> bytes:
    """
    Build a minimal DMARC aggregate report XML per RFC 7489 (feedback schema).
    pass_nets: source IPs from these nets will produce aligned (SPF=pass or DKIM=pass)
    fail_nets: source IPs from these nets will produce DMARC-fail (SPF=fail and DKIM=fail)
    """
    report_id = f"{int(time.time()*1000)}-{uuid.uuid4()}"
    root = ET.Element("feedback")
    # Report metadata
    rm = ET.SubElement(root, "report_metadata")
    ET.SubElement(rm, "org_name").text = org_name
    ET.SubElement(rm, "email").text = f"dmarc-reports@{report_domain}"
    ET.SubElement(rm, "report_id").text = report_id
    rng = ET.SubElement(rm, "date_range")
    ET.SubElement(rng, "begin").text = str(begin_ts)
    ET.SubElement(rng, "end").text = str(end_ts)

    # Policy published
    pp = ET.SubElement(root, "policy_published")
    ET.SubElement(pp, "domain").text = report_domain
    ET.SubElement(pp, "adkim").text = "r"
    ET.SubElement(pp, "aspf").text = "r"
    ET.SubElement(pp, "p").text = "none"
    ET.SubElement(pp, "sp").text = "none"
    ET.SubElement(pp, "pct").text = "100"

    # Decide how many records to emit: prefer 2–4 if both pools exist, else 1–3
    if pass_nets and fail_nets:
        count = random.randint(2, 4)
    else:
        count = random.randint(1, 3)

    # Ensure at least one from each pool if both exist
    pools = []
    if pass_nets:
        pools.append(("pass", pass_nets))
    if fail_nets:
        pools.append(("fail", fail_nets))
    if not pools:
        pools.append(("pass", []))  # everything random

    # Build records
    must_emit = []
    if len(pools) == 2 and count >= 2:
        # Guarantee one aligned + one failing
        must_emit = [("pass", pass_nets), ("fail", fail_nets)]

    for i in range(count):
        mode, nets = random.choice(pools)
        if must_emit:
            mode, nets = must_emit.pop(0)

        rec = ET.SubElement(root, "record")
        rid = ET.SubElement(rec, "row")

        ip = pick_ip_from_networks(nets)
        ET.SubElement(rid, "source_ip").text = ip
        ET.SubElement(rid, "count").text = str(random.randint(1, 7))
        pol = ET.SubElement(rid, "policy_evaluated")

        # DMARC evaluation logic for synthetic data:
        if mode == "pass":
            # At least one of SPF or DKIM passes; randomise which
            spf_ok = random.choice([True, False])
            dkim_ok = not spf_ok or random.choice([True, False])  # sometimes both pass
            # DMARC disposition 'none' (since p=none) even on fail; but we set results accordingly
            ET.SubElement(pol, "disposition").text = "none"
            ET.SubElement(pol, "dkim").text = "pass" if dkim_ok else "fail"
            ET.SubElement(pol, "spf").text = "pass" if spf_ok else "fail"
        else:
            # Fail case: both fail
            ET.SubElement(pol, "disposition").text = "none"
            ET.SubElement(pol, "dkim").text = "fail"
            ET.SubElement(pol, "spf").text = "fail"

        # Identifiers (relaxed alignment with header_from = report_domain)
        idf = ET.SubElement(rec, "identifiers")
        ET.SubElement(idf, "header_from").text = report_domain

        # Auth results block
        ar = ET.SubElement(rec, "auth_results")
        dkim_res = ET.SubElement(ar, "dkim")
        ET.SubElement(dkim_res, "domain").text = report_domain
        ET.SubElement(dkim_res, "result").text = "pass" if pol.findtext("dkim") == "pass" else "fail"

        spf_res = ET.SubElement(ar, "spf")
        ET.SubElement(spf_res, "domain").text = report_domain
        ET.SubElement(spf_res, "result").text = "pass" if pol.findtext("spf") == "pass" else "fail"

    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return xml_bytes

def gzip_bytes(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()

# ------------------------
# Email sending
# ------------------------
def build_message(
    from_addr: str,
    to_addr: str,
    org_name: str,
    report_domain: str,
    xml_gz: bytes,
    begin_ts: int,
    end_ts: int,
) -> EmailMessage:
    fn = f"{report_domain}!{begin_ts}!{end_ts}!{uuid.uuid4().hex}.xml.gz"
    subject = f"DMARC Aggregate Report for {report_domain} [{begin_ts}-{end_ts}]"
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(
        f"""DMARC aggregate report attached.

org: {org_name}
domain: {report_domain}
window: {begin_ts}–{end_ts} (Unix epoch)
file: {fn}
"""
    )
    msg.add_attachment(
        xml_gz,
        maintype="application",
        subtype="gzip",
        filename=fn,
    )
    return msg

def send_email(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    msg: EmailMessage,
    use_starttls: bool = True,
    use_ssl: bool = False,
):
    if use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as s:
            if username:
                s.login(username, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=60) as s:
            if use_starttls:
                s.starttls(context=ssl.create_default_context())
            if username:
                s.login(username, password)
            s.send_message(msg)

# ------------------------
# Driver
# ------------------------
def build_pools(pass_includes: str, fail_includes: str):
    pass_list = pass_includes.split() if pass_includes else []
    fail_list = fail_includes.split() if fail_includes else []
    pass_nets, pass_visited = resolve_spf_includes(pass_list)
    fail_nets, fail_visited = resolve_spf_includes(fail_list)
    return pass_nets, fail_nets, pass_visited, fail_visited

def run_once(args, pass_nets, fail_nets):
    now = datetime.now(timezone.utc)
    end = int(now.timestamp())
    begin = int((now - timedelta(hours=1)).timestamp())

    xml_raw = generate_dmarc_xml(args.org_name, args.report_domain, begin, end, pass_nets, fail_nets)
    xml_gz = gzip_bytes(xml_raw)
    msg = build_message(
        args.mail_from, args.mail_to, args.org_name, args.report_domain, xml_gz, begin, end
    )
    send_email(
        args.smtp_host,
        args.smtp_port,
        args.smtp_user or "",
        args.smtp_pass or "",
        msg,
        use_starttls=args.starttls,
        use_ssl=args.ssl,
    )

def run_hourly(args, pass_nets, fail_nets):
    while True:
        batch = random.randint(args.min_per_hour, args.max_per_hour)
        print(f"[{datetime.now().isoformat()}] Sending {batch} DMARC reports this hour...")
        base_sleep = 3600.0 / batch
        for i in range(batch):
            try:
                run_once(args, pass_nets, fail_nets)
                print(f"  sent {i+1}/{batch}")
            except Exception as e:
                print(f"  error on {i+1}/{batch}: {e}", file=sys.stderr)
            sleep_s = max(1.0, base_sleep * (1.0 + random.uniform(-0.2, 0.2)))
            if i < batch - 1:
                time.sleep(sleep_s)

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate & send synthetic DMARC aggregate reports at a steady hourly rate."
    )
    # Report identity
    p.add_argument("--org-name", default="ExampleOrg", help="Reporting org_name")
    p.add_argument("--report-domain", required=True, help="Domain being reported on (policy_published.domain)")
    # Email routing
    p.add_argument("--mail-from", required=True, help="SMTP From address")
    p.add_argument("--mail-to", required=True, help="Destination address to receive reports")
    p.add_argument("--smtp-host", required=True, help="SMTP host")
    p.add_argument("--smtp-port", type=int, default=587, help="SMTP port (587 STARTTLS, 465 SSL)")
    p.add_argument("--smtp-user", default=os.getenv("SMTP_USER", ""), help="SMTP username (or env SMTP_USER)")
    p.add_argument("--smtp-pass", default=os.getenv("SMTP_PASS", ""), help="SMTP password (or env SMTP_PASS)")
    p.add_argument("--ssl", action="store_true", help="Use SMTPS (port 465 typical)")
    p.add_argument("--no-starttls", dest="starttls", action="store_false", help="Disable STARTTLS (not recommended)")
    p.set_defaults(starttls=True)

    # Rate control
    p.add_argument("--min-per-hour", type=int, default=50, help="Minimum messages per hour")
    p.add_argument("--max-per-hour", type=int, default=100, help="Maximum messages per hour")

    # SPF include pools (space-separated)
    p.add_argument("--spf-pass-includes", default=os.getenv("SPF_PASS_INCLUDES", ""), help="Space-separated SPF includes used to generate DMARC-aligned (pass) records")
    p.add_argument("--spf-fail-includes", default=os.getenv("SPF_FAIL_INCLUDES", ""), help="Space-separated SPF includes used to generate DMARC-fail records")

    # Modes
    p.add_argument("--once", action="store_true", help="Send a single report and exit")
    return p.parse_args()

def main():
    args = parse_args()
    if args.min_per_hour < 1 or args.max_per_hour < args.min_per_hour:
        print("Invalid per-hour bounds", file=sys.stderr)
        sys.exit(2)

    pass_nets, fail_nets, pass_visited, fail_visited = build_pools(args.spf_pass_includes, args.spf_fail_includes)
    print(f"[init] pass_includes resolved: {', '.join(sorted(pass_visited)) or '(none)'}; nets={len(pass_nets)}")
    print(f"[init] fail_includes resolved: {', '.join(sorted(fail_visited)) or '(none)'}; nets={len(fail_nets)}")

    if args.once:
        run_once(args, pass_nets, fail_nets)
    else:
        run_hourly(args, pass_nets, fail_nets)

if __name__ == "__main__":
    main()
