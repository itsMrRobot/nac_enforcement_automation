#!/usr/bin/env python3
"""
Load MAC addresses into Cisco ISE (ERS) as an Endpoint Identity Group and report policy usage.

Intended to accept MAC output from meraki_mac_scraper.py (one per line) via stdin or a file.

Usage examples:
    python ise_mac_loader.py --site-name "My Branch" --ise-url https://ise.local:9060 \
        --username admin --password secret --mac-file macs.txt

    python meraki_mac_scraper.py --site-name "My Branch" | \
        python ise_mac_loader.py --site-name "My Branch" --ise-url https://ise.local:9060 \
        --username admin --password secret

Authentication:
    - Basic auth with ISE ERS API.
    - Credentials can be provided via --username/--password or env vars ISE_USERNAME/ISE_PASSWORD.

Notes:
    - The script creates (if needed) an Endpoint Identity Group named after the site.
    - Each MAC is added as an endpoint in that group if not already present.
    - A final check scans policy sets for references to the group name and prints True/False.
    - Use --dryrun to perform read-only validation (no creations/updates).
    - Parent Endpoint Identity Group defaults to "Sites" (override with --endpoint-parent).
"""

import argparse
import os
import sys
import time
from typing import Iterable, List, Optional, Set, Tuple

import requests


class ISEAPIError(RuntimeError):
    """Raised when Cisco ISE ERS API responds with a non-successful status."""


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
    Send an HTTP request to ISE ERS API with basic retry for rate limiting.

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
            raise ISEAPIError("Unauthorized: check ISE credentials or ERS access.")
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


def extract_id(resource: Optional[dict]) -> Optional[str]:
    """Extract an ID from various ISE response shapes."""
    if not isinstance(resource, dict):
        return None
    for key in ("id", "ID", "uuid", "groupId"):
        val = resource.get(key)
        if val:
            return val
    resp = resource.get("response")
    if isinstance(resp, dict):
        return extract_id(resp)
    return None


def get_endpoint_group(
    session: requests.Session, api_base: str, name: str
) -> Optional[dict]:
    """Return endpoint group dict if it exists, else None."""
    params = {"size": 100, "filter": f"name.EQ.{name}"}
    data, _ = request_ise(session, api_base, "GET", "/ers/config/endpointgroup", params=params)
    resources = data.get("SearchResult", {}).get("resources", []) if isinstance(data, dict) else []
    for item in resources:
        if item.get("name", "").lower() == name.lower():
            return item
    return None


def create_endpoint_group(
    session: requests.Session, api_base: str, name: str, description: str = "", parent_id: Optional[str] = None
) -> dict:
    """Create a new endpoint identity group."""
    payload = {
        "EndPointGroup": {
            "name": name,
            "description": description or f"MAC list for {name}",
            "systemDefined": False,
        }
    }
    if parent_id:
        payload["EndPointGroup"]["parentGroupId"] = parent_id
    data, _ = request_ise(session, api_base, "POST", "/ers/config/endpointgroup", json=payload)
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
    data, _ = request_ise(session, api_base, "GET", "/ers/config/endpoint", params=params)
    resources = data.get("SearchResult", {}).get("resources", []) if isinstance(data, dict) else []
    return resources[0] if resources else None


def create_endpoint(
    session: requests.Session, api_base: str, mac: str, group_id: str
) -> dict:
    """Create a new endpoint with the given MAC and group assignment."""
    payload = {
        "ERSEndPoint": {
            "name": mac,
            "mac": mac,
            "groupId": group_id,
        }
    }
    data, _ = request_ise(session, api_base, "POST", "/ers/config/endpoint", json=payload)
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
    data, _ = request_ise(session, api_base, "GET", "/ers/config/policyset")
    resources = data.get("SearchResult", {}).get("resources", []) if isinstance(data, dict) else []
    for item in resources:
        href = item.get("link", {}).get("href")
        if not href:
            continue
        body, _ = request_ise(session, api_base, "GET", href)
        body_str = str(body).lower()
        if group_name.lower() in body_str:
            return True
    return False


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load MAC addresses into Cisco ISE Endpoint Identity Group (ERS API)."
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
        help="Base URL for Cisco ISE ERS API (e.g., https://ise.example.com:9060).",
    )
    parser.add_argument(
        "--endpoint-parent",
        default="Sites",
        help='Parent Endpoint Identity Group name to nest the site group under (default: "Sites").',
    )
    parser.add_argument(
        "--username",
        default=os.getenv("ISE_USERNAME"),
        help="ISE ERS username (env ISE_USERNAME as fallback).",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("ISE_PASSWORD"),
        help="ISE ERS password (env ISE_PASSWORD as fallback).",
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

    session = requests.Session()
    session.auth = (args.username, args.password)
    session.verify = not args.insecure
    session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    try:
        parent_group = get_endpoint_group(session, api_base, args.endpoint_parent)
        group = get_endpoint_group(session, api_base, args.site_name)

        if args.dryrun:
            if not group:
                print(f"DRY RUN: Endpoint group '{args.site_name}' not found; skipping MAC and policy checks.")
                print(f"Parent group '{args.endpoint_parent}' exists: {bool(parent_group)}")
                return 0
            group_id = extract_id(group)
            if not group_id:
                raise ISEAPIError("Could not determine endpoint group ID.")
            existing, missing = check_macs(session, api_base, macs)
            in_policy = policy_uses_group(session, api_base, args.site_name)
        else:
            if not parent_group:
                parent_group = create_endpoint_group(session, api_base, args.endpoint_parent)
            parent_id = extract_id(parent_group)
            if not parent_id:
                raise ISEAPIError("Could not determine parent endpoint group ID.")

            if not group:
                group = create_endpoint_group(
                    session, api_base, args.site_name, parent_id=parent_id
                )
            group_id = extract_id(group)
            if not group_id:
                raise ISEAPIError("Could not determine endpoint group ID.")

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
