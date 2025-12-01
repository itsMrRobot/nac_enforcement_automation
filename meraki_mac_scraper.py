#!/usr/bin/env python3
"""
Scrape active client MAC addresses for a single Meraki site (network).

Usage:
    python meraki_mac_scraper.py --site-name "My Branch" [--org-id ORG_ID] [--timespan 86400]

Required:
    - MERAKI_API_KEY environment variable or --api-key argument
"""

import argparse
import os
import sys
import time
from typing import Iterable, List, Set, Tuple

import requests

API_BASE = "https://api.meraki.com/api/v1"


class MerakiAPIError(RuntimeError):
    """Raised when the Meraki API responds with a non-successful status."""


def meraki_request(
    session: requests.Session, method: str, url: str, *, params=None
) -> Tuple[object, str]:
    """
    Make a Meraki API request with basic 429 backoff and pagination support.

    Returns a tuple of (json, next_url) where next_url is pulled from Link headers when present.
    """
    while True:
        response = session.request(method, url, params=params)

        if response.status_code == 429:
            wait = int(response.headers.get("Retry-After", "1"))
            time.sleep(wait)
            continue

        if not response.ok:
            raise MerakiAPIError(
                f"Meraki API error {response.status_code}: {response.text}"
            )

        next_url = ""
        link_header = response.headers.get("Link", "")
        if link_header:
            # Meraki follows RFC 5988; look for rel="next"
            parts = [p.strip() for p in link_header.split(",")]
            for part in parts:
                if 'rel="next"' in part:
                    start = part.find("<") + 1
                    end = part.find(">", start)
                    next_url = part[start:end]
                    break

        return response.json(), next_url


def resolve_org_id(session: requests.Session, org_id: str | None) -> str:
    """Return the organization ID, auto-selecting if only one is available."""
    if org_id:
        return org_id

    data, _ = meraki_request(session, "GET", f"{API_BASE}/organizations")
    if not isinstance(data, list) or not data:
        raise MerakiAPIError("No organizations returned for this API key.")

    if len(data) == 1:
        return data[0]["id"]

    names = ", ".join(f'{org["name"]} ({org["id"]})' for org in data)
    raise MerakiAPIError(
        f"Multiple organizations found; please specify one with --org-id. Available: {names}"
    )


def find_network_id(
    session: requests.Session, org_id: str, site_name: str
) -> str:
    """Find the network ID for the provided site name (case-insensitive)."""
    params = {"perPage": 1000}
    url = f"{API_BASE}/organizations/{org_id}/networks"
    matches: List[dict] = []

    while url:
        data, next_url = meraki_request(session, "GET", url, params=params)
        params = None  # Only include params on the first call
        for net in data:
            if net.get("name", "").lower() == site_name.lower():
                matches.append(net)
        url = next_url

    if not matches:
        raise MerakiAPIError(f'No network found matching site name "{site_name}".')
    if len(matches) > 1:
        ids = ", ".join(net["id"] for net in matches)
        raise MerakiAPIError(
            f'Multiple networks found for "{site_name}". Please disambiguate via --org-id or rename duplicates. IDs: {ids}'
        )

    return matches[0]["id"]


def list_active_client_macs(
    session: requests.Session, network_id: str, timespan: int
) -> Set[str]:
    """Return a set of MAC addresses for active clients in the given network."""
    params = {"perPage": 1000, "timespan": timespan}
    url = f"{API_BASE}/networks/{network_id}/clients"
    macs: Set[str] = set()

    while url:
        data, next_url = meraki_request(session, "GET", url, params=params)
        params = None  # Params already applied on first call
        if isinstance(data, list):
            for client in data:
                mac = client.get("mac")
                if mac:
                    macs.add(mac)
        url = next_url

    return macs


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scrape active client MAC addresses from a Meraki site."
    )
    parser.add_argument(
        "--site-name",
        required=True,
        help="Name of the Meraki network/site to query.",
    )
    parser.add_argument(
        "--org-id",
        help="Meraki organization ID. Optional if your API key has access to only one org.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("MERAKI_API_KEY"),
        help="Meraki API key. Defaults to MERAKI_API_KEY environment variable.",
    )
    parser.add_argument(
        "--timespan",
        type=int,
        default=86400,
        help="Seconds to look back for active clients (default: 86400).",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)

    if not args.api_key:
        print("Error: Meraki API key must be provided via --api-key or MERAKI_API_KEY.", file=sys.stderr)
        return 1

    session = requests.Session()
    session.headers.update({"X-Cisco-Meraki-API-Key": args.api_key})

    try:
        org_id = resolve_org_id(session, args.org_id)
        network_id = find_network_id(session, org_id, args.site_name)
        macs = list_active_client_macs(session, network_id, args.timespan)
    except MerakiAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    for mac in sorted(macs):
        print(mac)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
