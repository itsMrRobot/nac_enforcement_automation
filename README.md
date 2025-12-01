# NAC Enforcement Automation

Scripts for gathering active client MAC addresses from Cisco Meraki and loading them into Cisco ISE.

## Prerequisites
- Python 3.9+ installed.
- Cisco Meraki Dashboard API key with access to the target organization/network.
- Cisco ISE ERS API reachable (e.g., `https://ise.example.com:9060`), with credentials that can manage Endpoint Identity Groups and Endpoints. Make sure ERS is enabled on your ISE version.
- (Optional) Ability to disable TLS verification for lab/self-signed ISE via `--insecure`.

## Setup (venv)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Scripts
- `meraki_mac_scraper.py`: Pull active client MACs from a Meraki site (network).
- `ise_mac_loader.py`: (ISE ERS) Create/ensure a matching Endpoint Identity Group in ISE and load those MACs as endpoints, then report if any policy references that group.

## Usage

### 1) Scrape MACs from Meraki
Set your Meraki API key:
```bash
export MERAKI_API_KEY="your_meraki_api_key"
```
Run the scraper (uses timespan 86400s by default):
```bash
python meraki_mac_scraper.py --site-name "My Branch"
```
If your key has multiple orgs, add `--org-id ORG_ID`. Adjust lookback with `--timespan SECONDS`.

### 2) Load MACs into ISE
Set ISE credentials (or use flags):
```bash
export ISE_USERNAME="ise_user"
export ISE_PASSWORD="ise_password"
```
Pipe the Meraki output into ISE loader:
```bash
python meraki_mac_scraper.py --site-name "My Branch" \
  | python ise_mac_loader.py --site-name "My Branch" \
      --ise-url https://ise.example.com:9060 \
      --username "$ISE_USERNAME" --password "$ISE_PASSWORD"
```
Site groups are nested under a parent Endpoint Group (default: `Sites`). Provide a different parent with `--endpoint-parent "MyParent"`.
Run in dry-run (read-only) mode to validate without creating/updating:
```bash
python meraki_mac_scraper.py --site-name "My Branch" \
  | python ise_mac_loader.py --site-name "My Branch" \
      --ise-url https://ise.example.com:9060 \
      --username "$ISE_USERNAME" --password "$ISE_PASSWORD" \
      --dryrun
```
Dry-run will stop after reporting that the endpoint group is missing if it does not already exist.
Alternatively, read MACs from a file:
```bash
python ise_mac_loader.py --site-name "My Branch" \
  --ise-url https://ise.example.com:9060 \
  --mac-file macs.txt \
  --username "$ISE_USERNAME" --password "$ISE_PASSWORD"
```

### 3) Outputs
- `meraki_mac_scraper.py` prints MACs (one per line).
- `ise_mac_loader.py` prints:
  - The endpoint group name/ID (created if missing).
  - Counts of processed/created/existing MACs.
  - Whether any policy set references the group name (`True`/`False`).

## Options and Flags
- Meraki scraper:
  - `--site-name` (required)
  - `--org-id` (optional; required if multiple orgs)
  - `--api-key` (optional; defaults to `MERAKI_API_KEY`)
  - `--timespan` (seconds; default 86400)
- ISE loader:
  - `--site-name` (required; becomes Endpoint Identity Group name)
  - `--mac-file` (optional; defaults to stdin)
  - `--ise-url` (required; e.g., `https://ise.example.com:9060`)
  - `--endpoint-parent` (optional; parent Endpoint Group name; default `Sites`)
  - `--username` / `--password` (flags or env `ISE_USERNAME`/`ISE_PASSWORD`)
  - `--insecure` (disable TLS verification for lab/self-signed)
  - `--dryrun` (validate only; no creations/updates)
  - Site names are normalized to alphanumeric/underscore/dash (invalid characters become `_`).

## Notes
- The ISE loader uses the Endpoint Identity Group model via ERS endpoints (e.g., `/ers/config/endpointgroup`, `/ers/config/endpoint`, `/ers/config/policyset`). Ensure ERS is enabled.
- Policy reference check is best-effort: it scans policy sets for the group name string. Tailor it if you need a stricter linkage.
- When not running `--dryrun`, the loader will create the parent Endpoint Group (default `Sites`) if it is missing, then create the site group under it.
- Handle credentials securely (avoid committing them). Use environment variables or a secrets manager where possible.
