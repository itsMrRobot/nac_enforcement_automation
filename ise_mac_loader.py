#!/usr/bin/env python3
"""
Load MAC addresses into Cisco ISE (OpenAPI, 3.x+) as an Endpoint Identity Group and report policy usage.

Intended to accept MAC output from meraki_mac_scraper.py (one per line) via stdin or a file.

Usage examples:
    python ise_mac_loader.py --site-name "My Branch" --ise-url https://ise.local:443/api/v1 \
        --username admin --password secret --mac-file macs.txt

    python meraki_mac_scraper.py --site-name "My Branch" | \
        python ise_mac_loader.py --site-name "My Branch" --ise-url https://ise.local:443/api/v1 \
        --username admin --password secret
    (If you provide only the host, the script appends /api/v1 automatically.)

Authentication:
    - Basic auth with ISE OpenAPI (3.x+).
    - Credentials can be provided via --username/--password or env vars ISE_USERNAME/ISE_PASSWORD.

Notes:
    - The script creates (if needed) an Endpoint Identity Group named after the site.
    - Each MAC is added as an endpoint in that group if not already present.
    - A final check scans policy sets for references to the group name and prints True/False.
    - Use --dryrun to perform read-only validation (no creations/updates).
"""

import argparse
import os
import sys
import time
from typing import Iterable, List, Optional, Set, Tuple

import requests


class ISEAPIError(RuntimeError):
    """Raised when Cisco ISE OpenAPI responds with a non-successful status."""


def request_ise(
    session: requests.Session,
    api_base: str,
    method: str,
    path: str,
    *,
    params: Optional[dict] = None,
    json: Optional[dict] = None,
) -> Tuple[object, dict]:
    """
    Send an HTTP request to ISE OpenAPI with basic retry for rate limiting.

    Returns (json_body, headers).
    """
    url = f"{api_base.rstrip('/')}/{path.lstrip('/')}"
    while True:
        resp = session.request(method, url, params=params, json=json)
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", "1"))
            time.sleep(wait)
            continue
        if resp.status_code == 401:
            raise ISEAPIError("Unauthorized: check ISE credentials or OpenAPI access.")
        if not resp.ok:
            raise ISEAPIError(
                f"ISE API error {resp.status_code} for {path}: {resp.text}"
            )
        try:
            body = resp.json()
        except ValueError:
            body = {}
        return body, resp.headers


def read_macs(stdin_data: Iterable[str]) -> List[str]:
    """Parse MAC addresses (one per line), returning normalized unique list preserving order."""
    seen: Set[str] = set()
    macs: List[str] = []
    for line in stdin_data:
        mac = line.strip()
        if not mac:
            continue
        if mac not in seen:
            seen.add(mac)
            macs.append(mac)
    return macs


def get_endpoint_group(
    session: requests.Session, api_base: str, name: str
) -> Optional[dict]:
    """Return endpoint group dict if it exists, else None."""
    params = {"size": 100, "filter": f"name.EQ.{name}"}
    data, _ = request_ise(session, api_base, "GET", "/endpoint-group", params=params)
    items = []
    if isinstance(data, dict):
        items = data.get("response", data.get("resources", [])) or data.get("SearchResult", {}).get("resources", [])
    for item in items:
        item_name = item.get("name") or item.get("description") or ""
        if item_name.lower() == name.lower():
            return item
    return None


def create_endpoint_group(
    session: requests.Session, api_base: str, name: str, description: str = ""
) -> dict:
    """Create a new endpoint identity group."""
    payload = {
        "name": name,
        "description": description or f"MAC list for {name}",
        "systemDefined": False,
    }
    data, _ = request_ise(session, api_base, "POST", "/endpoint-group", json=payload)
    return data


def ensure_endpoint_group(
    session: requests.Session, api_base: str, site_name: str, create_missing: bool = True
) -> Optional[dict]:
    """Fetch the endpoint group for the site, optionally creating it when missing."""
    group = get_endpoint_group(session, api_base, site_name)
    if group or not create_missing:
        return group
    return create_endpoint_group(session, api_base, site_name)


def get_endpoint_by_mac(
    session: requests.Session, api_base: str, mac: str
) -> Optional[dict]:
    """Return endpoint resource for a MAC if it exists."""
    params = {"size": 1, "filter": f"mac.EQ.{mac}"}
    data, _ = request_ise(session, api_base, "GET", "/endpoint", params=params)
    items = []
    if isinstance(data, dict):
        items = data.get("response", data.get("resources", [])) or data.get("SearchResult", {}).get("resources", [])
    return items[0] if items else None


def create_endpoint(
    session: requests.Session, api_base: str, mac: str, group_id: str
) -> dict:
    """Create a new endpoint with the given MAC and group assignment."""
    payload = {
        "name": mac,
        "mac": mac,
        "groupId": group_id,
    }
    data, _ = request_ise(session, api_base, "POST", "/endpoint", json=payload)
    return data


def add_macs_to_group(
    session: requests.Session, api_base: str, macs: List[str], group_id: str
) -> Tuple[int, int]:
    """Ensure each MAC exists in ISE within the specified group. Returns (created, skipped)."""
    created = 0
    skipped = 0
    for mac in macs:
        existing = get_endpoint_by_mac(session, api_base, mac)
        if existing:
            skipped += 1
            continue
        create_endpoint(session, api_base, mac, group_id)
        created += 1
    return created, skipped


def check_macs(
    session: requests.Session, api_base: str, macs: List[str]
) -> Tuple[int, int]:
    """Count how many provided MACs already exist in ISE. Returns (existing, missing)."""
    existing = 0
    missing = 0
    for mac in macs:
        if get_endpoint_by_mac(session, api_base, mac):
            existing += 1
        else:
            missing += 1
    return existing, missing


def policy_uses_group(
    session: requests.Session, api_base: str, group_name: str
) -> bool:
    """
    Best-effort check if any policy set references the endpoint group name.

    ISE does not expose a simple lookup for group usage; this scans policy sets
    and authorization policies textually for the group name.
    """
    data, _ = request_ise(session, api_base, "GET", "/policy-sets")
    items = data.get("response") if isinstance(data, dict) else []
    if items is None:
        items = data.get("resources", []) if isinstance(data, dict) else []
    for item in items:
        # Fetch full policy set details
        policy_id = item.get("id") or item.get("policySetId")
        if not policy_id:
            continue
        body, _ = request_ise(session, api_base, "GET", f"/policy-sets/{policy_id}")
        body_str = str(body).lower()
        if group_name.lower() in body_str:
            return True
    return False


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load MAC addresses into Cisco ISE Endpoint Identity Group (OpenAPI 3.x+)."
    )
    parser.add_argument(
        "--site-name",
        required=True,
        help="Name of the site / Endpoint Identity Group to target.",
    )
    parser.add_argument(
        "--mac-file",
        help="File containing MAC addresses (one per line). Defaults to stdin.",
    )
    parser.add_argument(
        "--ise-url",
        required=True,
        help="Base URL for Cisco ISE OpenAPI host or /api/v1 (e.g., https://ise.example.com or https://ise.example.com:443/api/v1).",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("ISE_USERNAME"),
        help="ISE OpenAPI username (env ISE_USERNAME as fallback).",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("ISE_PASSWORD"),
        help="ISE OpenAPI password (env ISE_PASSWORD as fallback).",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (useful for lab/self-signed; not recommended for production).",
    )
    parser.add_argument(
        "--dryrun",
        action="store_true",
        help="Read-only: validate group/MAC/policy existence without creating or updating anything.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)

    if not args.username or not args.password:
        print("Error: ISE credentials are required (--username/--password or env vars).", file=sys.stderr)
        return 1

    # Load MACs
    if args.mac_file:
        with open(args.mac_file, "r", encoding="utf-8") as fh:
            macs = read_macs(fh)
    else:
        macs = read_macs(sys.stdin)

    if not macs:
        print("No MAC addresses provided.", file=sys.stderr)
        return 1

    api_base = args.ise_url.rstrip("/")
    if not api_base.endswith("/api/v1"):
        api_base = f"{api_base}/api/v1"

    session = requests.Session()
    session.auth = (args.username, args.password)
    session.verify = not args.insecure
    session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    try:
        group = get_endpoint_group(session, api_base, args.site_name)
        if not group:
            if args.dryrun:
                print("DRY RUN: Endpoint group not found; skipping MAC and policy checks.")
                return 0
            group = create_endpoint_group(session, api_base, args.site_name)

        group_id = group.get("id") or group.get("ID") or group.get("uuid")
        if not group_id:
            raise ISEAPIError("Could not determine endpoint group ID.")

        if args.dryrun:
            existing, missing = check_macs(session, api_base, macs)
            in_policy = policy_uses_group(session, api_base, args.site_name)
        else:
            created, skipped = add_macs_to_group(session, api_base, macs, group_id)
            in_policy = policy_uses_group(session, api_base, args.site_name)
    except (ISEAPIError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.dryrun:
        print("DRY RUN: no changes applied.")
        print(f"Endpoint group exists: {bool(group)}" + (f" (id={group_id})" if group_id else ""))
        print(f"MACs provided: {len(macs)} | existing in ISE: {existing} | missing: {missing}")
        print(f"Policy references group: {in_policy}")
        return 0

    print(f"Endpoint group: {args.site_name} (id={group_id})")
    print(f"MACs processed: {len(macs)} | created: {created} | existing: {skipped}")
    print(f"Policy references group: {in_policy}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
