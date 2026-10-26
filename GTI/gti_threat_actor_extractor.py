#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""GTI Threat Actor Extractor.

This script demonstrates the optimal, best-practice approach to retrieve complete
Threat Actor profiles (Header, Overview, Associated Malware, Tools, Vulnerabilities,
and MITRE ATT&CK TTPs) from the Google Threat Intelligence (GTI) API.

Instead of making thousands of paginated API calls (~5,000 calls for ~700 actors),
this script optimizes the workflow into:
  1. Top-level collection query with cursor pagination (already includes all
     Header + Overview attributes: ~18 calls total for ~700 actors).
  2. Single-call relationship expansion per actor for associations (malware,
     tools, campaigns, reports): 1 call per actor.
  3. Dedicated vulnerability retrieval (/collections/{actor_id}/vulnerabilities)
     to pull all associated CVEs with attributes and optional deep CVSS/EPSS enrichment.
  4. Single-call MITRE ATT&CK tree retrieval per actor: 1 call per actor.
  5. Optional industry, regional, or delta-time filtering to further reduce calls
     to only relevant adversaries (e.g. Energy & Utilities in Europe).

Usage:
  # Test with a single threat actor:
  python3 gti_threat_actor_extractor.py --api-key <YOUR_KEY> --actor-name "UNC6266"

  # Test with Energy & Utilities sector (first 5 actors) including vulnerabilities:
  python3 gti_threat_actor_extractor.py --api-key <YOUR_KEY> --industry "Energy & Utilities" --limit 5

  # Include deep vulnerability intelligence (CVSS metrics, EPSS, in-the-wild exploitation):
  python3 gti_threat_actor_extractor.py --api-key <YOUR_KEY> --actor-name "APT28" --enrich-vulnerabilities

  # Incremental sync (actors modified in the last 7 days):
  python3 gti_threat_actor_extractor.py --api-key <YOUR_KEY> --delta-days 7
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
  import requests
except ImportError:
  requests = None


class GtiApiClient:
  """Client for interacting with the Google Threat Intelligence (GTI) API."""

  BASE_URL = "https://www.virustotal.com/api/v3"

  def __init__(self, api_key: str, max_retries: int = 3, backoff_factor: float = 2.0):
    if not api_key:
      raise ValueError("A valid GTI API key is required.")
    self.api_key = api_key
    self.max_retries = max_retries
    self.backoff_factor = backoff_factor
    self.call_count = 0

    if requests:
      self.session = requests.Session()
      self.session.headers.update({
          "x-apikey": self.api_key,
          "Accept": "application/json",
          "User-Agent": "GTI-ThreatActor-Extractor/1.1",
      })
    else:
      self.session = None

  def _request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Sends a GET request with exponential backoff on 429 / 5xx errors."""
    url = f"{self.BASE_URL}{endpoint}"
    self.call_count += 1

    for attempt in range(1, self.max_retries + 1):
      try:
        if self.session:
          response = self.session.get(url, params=params, timeout=30)
          if response.status_code == 429:
            sleep_time = self.backoff_factor ** attempt
            logging.warning(
                "Rate limit encountered (HTTP 429). Retrying in %.1fs (attempt %d/%d)...",
                sleep_time, attempt, self.max_retries,
            )
            time.sleep(sleep_time)
            continue

          response.raise_for_status()
          return response.json()
        else:
          query_str = f"?{urllib.parse.urlencode(params)}" if params else ""
          req = urllib.request.Request(
              f"{url}{query_str}",
              headers={
                  "x-apikey": self.api_key,
                  "Accept": "application/json",
                  "User-Agent": "GTI-ThreatActor-Extractor/1.1",
              },
          )
          with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

      except Exception as exc:
        if attempt == self.max_retries:
          logging.error("Failed request to %s after %d attempts: %s", url, attempt, exc)
          raise
        sleep_time = self.backoff_factor ** attempt
        logging.warning("Request error (%s). Retrying in %.1fs...", exc, sleep_time)
        time.sleep(sleep_time)

    return {}

  def list_threat_actors(
      self,
      actor_name: Optional[str] = None,
      industry_group: Optional[str] = None,
      region: Optional[str] = None,
      delta_days: Optional[int] = None,
      limit: Optional[int] = None,
      page_size: int = 40,
  ) -> List[Dict[str, Any]]:
    """Retrieves threat actors matching the specified criteria.

    Note: The /collections listing endpoint returns the FULL threat actor
    attributes (Header + Overview) in each data element!
    """
    filters = ["collection_type:threat-actor"]

    if actor_name:
      filters.append(f"name:{actor_name}")
    if industry_group:
      filters.append(f"targeted_industry_group:'{industry_group}'")
    if region:
      filters.append(f"targeted_region:{region}")
    if delta_days:
      filters.append(f"last_modification_date:{delta_days}d+")

    filter_str = " ".join(filters)
    logging.info("Listing threat actors with filter: %s", filter_str)

    actors = []
    cursor = None

    while True:
      if limit and limit > 0:
        remaining = limit - len(actors)
        if remaining <= 0:
          break
        req_limit = min(page_size, remaining)
      else:
        req_limit = page_size

      params: Dict[str, Any] = {
          "filter": filter_str,
          "limit": req_limit,
      }
      if cursor:
        params["cursor"] = cursor

      result = self._request("/collections", params=params)
      data = result.get("data", [])
      if not data:
        break

      actors.extend(data)
      cursor = result.get("meta", {}).get("cursor")
      if not cursor:
        break

    return actors

  def get_actor_associations(self, actor_id: str) -> Dict[str, Any]:
    """Retrieves associated malware, tools, vulnerabilities, and campaigns in 1 call."""
    params = {
        "relationships": "associations",
        "relationship_attributes": "name,description,collection_type",
    }
    result = self._request(f"/collections/{actor_id}", params=params)
    data = result.get("data", {})
    relationships = data.get("relationships", {}).get("associations", {}).get("data", [])

    categorized: Dict[str, List[Dict[str, str]]] = {
        "malware_families": [],
        "software_toolkits": [],
        "vulnerabilities": [],
        "campaigns": [],
        "reports": [],
        "other": [],
    }

    for item in relationships:
      obj_type = item.get("type", "")
      obj_id = item.get("id", "")
      attrs = item.get("attributes", {})
      name = attrs.get("name", obj_id)
      desc = attrs.get("description", "")
      coll_type = attrs.get("collection_type", obj_type)

      entry = {"id": obj_id, "name": name, "description": desc}

      if coll_type == "malware-family" or obj_type == "malware-family":
        categorized["malware_families"].append(entry)
      elif coll_type == "software-toolkit" or obj_type == "software-toolkit":
        categorized["software_toolkits"].append(entry)
      elif coll_type == "vulnerability" or obj_type == "vulnerability":
        categorized["vulnerabilities"].append(entry)
      elif coll_type == "campaign" or obj_type == "campaign":
        categorized["campaigns"].append(entry)
      elif coll_type == "report" or obj_type == "report":
        categorized["reports"].append(entry)
      else:
        categorized["other"].append(entry)

    return categorized

  def get_actor_vulnerabilities(
      self,
      actor_id: str,
      limit: Optional[int] = None,
      page_size: int = 40,
      enrich_details: bool = False,
  ) -> List[Dict[str, Any]]:
    """Retrieves all vulnerabilities (CVEs) associated with a threat actor.

    Queries the /collections/{actor_id}/vulnerabilities endpoint using cursor
    pagination to retrieve full vulnerability objects linked to the actor.
    Optionally enriches each CVE with deep vulnerability metrics from
    /vulnerabilities/{cve_id} if enrich_details is True.

    Args:
      actor_id: The GTI collection ID of the threat actor (e.g. 'UNC6266' or UUID).
      limit: Maximum number of vulnerabilities to return (None for all).
      page_size: Number of items per request page (max 40).
      enrich_details: If True, makes an additional call per CVE to /vulnerabilities/{cve_id}
        to fetch CVSS scores, exploitation probability, EPSS, and in-the-wild status.

    Returns:
      A list of dictionaries representing the associated vulnerabilities.
    """
    vulnerabilities = []
    cursor = None

    while True:
      if limit and limit > 0:
        remaining = limit - len(vulnerabilities)
        if remaining <= 0:
          break
        req_limit = min(page_size, remaining)
      else:
        req_limit = page_size

      params: Dict[str, Any] = {"limit": req_limit}
      if cursor:
        params["cursor"] = cursor

      try:
        result = self._request(f"/collections/{actor_id}/vulnerabilities", params=params)
      except Exception as exc:
        logging.warning("Failed to fetch vulnerabilities for %s: %s", actor_id, exc)
        break

      data = result.get("data", [])
      if not data:
        break

      for item in data:
        vuln_id = item.get("id", "")
        attrs = item.get("attributes", {})
        cve_id = attrs.get("cve") or vuln_id

        vuln_entry: Dict[str, Any] = {
            "id": vuln_id,
            "cve": cve_id,
            "name": attrs.get("name", cve_id),
            "description": attrs.get("description", ""),
            "risk_rating": attrs.get("risk_rating", attrs.get("severity", "")),
            "cvss_score": attrs.get("cvss_score") or attrs.get("cvss", {}).get("score"),
            "creation_date": attrs.get("creation_date"),
            "last_modification_date": attrs.get("last_modification_date"),
            "tags": attrs.get("tags", []),
        }

        if enrich_details and cve_id:
          try:
            details = self.get_vulnerability_details(cve_id)
            if details:
              vuln_entry["enrichment"] = details
          except Exception as exc:
            logging.debug("Could not enrich CVE %s: %s", cve_id, exc)

        vulnerabilities.append(vuln_entry)

      cursor = result.get("meta", {}).get("cursor")
      if not cursor:
        break

    return vulnerabilities

  def get_vulnerability_details(self, cve_id: str) -> Dict[str, Any]:
    """Retrieves detailed vulnerability intelligence from the /vulnerabilities/{cve_id} endpoint.

    Args:
      cve_id: The CVE identifier (e.g. 'CVE-2023-38831').

    Returns:
      A dictionary containing CVSS metrics, EPSS score, exploitation state, and references.
    """
    try:
      result = self._request(f"/vulnerabilities/{cve_id}")
      data = result.get("data", {})
      attrs = data.get("attributes", {})
      return {
          "cve": attrs.get("cve", cve_id),
          "name": attrs.get("name", ""),
          "description": attrs.get("description", ""),
          "risk_rating": attrs.get("risk_rating", ""),
          "cvss_v3": attrs.get("cvss_v3", {}),
          "epss_score": attrs.get("epss_score"),
          "exploited_in_wild": attrs.get("exploited_in_wild", False),
          "patch_available": attrs.get("patch_available", False),
          "references": attrs.get("references", []),
      }
    except Exception as exc:
      logging.warning("Could not retrieve vulnerability details for %s: %s", cve_id, exc)
      return {}

  def get_actor_mitre_tree(self, actor_id: str, ttp_source: str = "operational") -> List[Dict[str, Any]]:
    """Retrieves the complete ATT&CK tactics and techniques hierarchy in 1 call."""
    params = {"filter": f"source:{ttp_source}"} if ttp_source else None
    try:
      result = self._request(f"/collections/{actor_id}/mitre_tree", params=params)
      tactics = result.get("data", {}).get("tactics", [])
      return tactics
    except Exception as exc:
      logging.warning("Could not retrieve MITRE tree for %s: %s", actor_id, exc)
      return []


def parse_threat_actor(
    raw_actor: Dict[str, Any],
    client: GtiApiClient,
    fetch_associations: bool = True,
    fetch_vulnerabilities: bool = True,
    enrich_vulnerabilities: bool = False,
    vuln_limit: Optional[int] = None,
    fetch_ttps: bool = True,
) -> Dict[str, Any]:
  """Constructs a consolidated Threat Actor profile."""
  actor_id = raw_actor.get("id", "")
  attrs = raw_actor.get("attributes", {})

  profile: Dict[str, Any] = {
      "id": actor_id,
      "name": attrs.get("name", ""),
      "description": attrs.get("description", ""),
      "alt_names": attrs.get("alt_names", []),
      "source_region": attrs.get("source_region", ""),
      "sponsor_region": attrs.get("sponsor_region", ""),
      "motivations": [m.get("value") if isinstance(m, dict) else m for m in attrs.get("motivations", [])],
      "targeted_regions": attrs.get("targeted_regions", []),
      "targeted_industries": attrs.get("targeted_industries", []),
      "first_seen": attrs.get("first_seen_details", []),
      "last_seen": attrs.get("last_seen_details", []),
      "malware_roles": [r.get("value") if isinstance(r, dict) else r for r in attrs.get("malware_roles", [])],
      "capabilities": [c.get("value") if isinstance(c, dict) else c for c in attrs.get("capabilities", [])],
      "tags": attrs.get("tags", []),
      "last_modification_date": attrs.get("last_modification_date"),
      "counters": attrs.get("counters", {}),
      "associations": {},
      "vulnerabilities": [],
      "ttps": [],
  }

  if fetch_associations:
    logging.info("Fetching associations for %s (%s)...", profile["name"], actor_id)
    profile["associations"] = client.get_actor_associations(actor_id)

  if fetch_vulnerabilities:
    logging.info("Fetching associated vulnerabilities for %s (%s)...", profile["name"], actor_id)
    profile["vulnerabilities"] = client.get_actor_vulnerabilities(
        actor_id=actor_id,
        limit=vuln_limit,
        enrich_details=enrich_vulnerabilities,
    )

  if fetch_ttps:
    logging.info("Fetching MITRE TTPs for %s (%s)...", profile["name"], actor_id)
    tactics = client.get_actor_mitre_tree(actor_id)
    ttp_summary = []
    for t in tactics:
      tactic_name = t.get("name", "")
      for tech in t.get("techniques", []):
        ttp_summary.append({
            "tactic": tactic_name,
            "technique_id": tech.get("id", ""),
            "technique_name": tech.get("name", ""),
            "subtechniques": [sub.get("id") for sub in tech.get("subtechniques", [])],
        })
    profile["ttps"] = ttp_summary

  return profile


def main():
  parser = argparse.ArgumentParser(
      description="Efficiently extract Threat Actor profiles, associations, vulnerabilities, and TTPs from the GTI API."
  )
  parser.add_argument(
      "--api-key",
      default=os.environ.get("GTI_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY"),
      help="GTI / VirusTotal API Key (defaults to GTI_API_KEY or VIRUSTOTAL_API_KEY env var).",
  )
  parser.add_argument(
      "--actor-name",
      help="Filter by specific threat actor name (e.g. 'UNC6266', 'APT28').",
  )
  parser.add_argument(
      "--industry",
      default=None,
      help="Filter by targeted industry group (e.g. 'Energy & Utilities', 'Financial Services').",
  )
  parser.add_argument(
      "--region",
      default=None,
      help="Filter by targeted region ISO code (e.g. 'DE', 'US').",
  )
  parser.add_argument(
      "--delta-days",
      type=int,
      default=None,
      help="Incremental sync: only fetch threat actors modified in the last N days (e.g. 7).",
  )
  parser.add_argument(
      "--limit",
      type=int,
      default=5,
      help="Max number of threat actors to process (default: 5. Use 0 or negative for all matching).",
  )
  parser.add_argument(
      "--vuln-limit",
      type=int,
      default=None,
      help="Max number of vulnerabilities to fetch per actor (default: all).",
  )
  parser.add_argument(
      "--no-associations",
      action="store_true",
      help="Skip fetching associated malware/tools/campaigns.",
  )
  parser.add_argument(
      "--no-vulnerabilities",
      action="store_true",
      help="Skip fetching associated vulnerabilities.",
  )
  parser.add_argument(
      "--enrich-vulnerabilities",
      action="store_true",
      help="Fetch deep vulnerability intelligence (CVSS metrics, EPSS, wild exploitation) via /vulnerabilities/{cve}.",
  )
  parser.add_argument(
      "--no-ttps",
      action="store_true",
      help="Skip fetching MITRE ATT&CK TTPs.",
  )
  parser.add_argument(
      "--output",
      default="threat_actors_export.json",
      help="File path to save the JSON output (default: threat_actors_export.json).",
  )
  parser.add_argument(
      "--verbose",
      action="store_true",
      help="Enable verbose debug logging.",
  )

  args = parser.parse_args()

  log_level = logging.DEBUG if args.verbose else logging.INFO
  logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")

  if not args.api_key:
    logging.error(
        "No API key provided. Please pass --api-key or set GTI_API_KEY / VIRUSTOTAL_API_KEY environment variable."
    )
    sys.exit(1)

  client = GtiApiClient(api_key=args.api_key)

  start_time = time.time()
  print("=" * 70)
  print(" GTI Threat Actor Optimized Extractor (with Vulnerability Support)")
  print("=" * 70)

  raw_actors = client.list_threat_actors(
      actor_name=args.actor_name,
      industry_group=args.industry,
      region=args.region,
      delta_days=args.delta_days,
      limit=args.limit,
  )

  print(f"\n[+] Found {len(raw_actors)} matching Threat Actor(s).")

  consolidated_actors = []
  for idx, actor in enumerate(raw_actors, start=1):
    name = actor.get("attributes", {}).get("name", "Unknown")
    actor_id = actor.get("id", "")
    print(f"[{idx}/{len(raw_actors)}] Processing: {name} (ID: {actor_id})...")

    parsed = parse_threat_actor(
        raw_actor=actor,
        client=client,
        fetch_associations=not args.no_associations,
        fetch_vulnerabilities=not args.no_vulnerabilities,
        enrich_vulnerabilities=args.enrich_vulnerabilities,
        vuln_limit=args.vuln_limit,
        fetch_ttps=not args.no_ttps,
    )
    consolidated_actors.append(parsed)

  with open(args.output, "w", encoding="utf-8") as f:
    json.dump(consolidated_actors, f, indent=2, ensure_ascii=False)

  elapsed = time.time() - start_time

  num_actors = len(consolidated_actors)
  total_vulns = sum(len(a.get("vulnerabilities", [])) for a in consolidated_actors)
  naive_calls = (
      (num_actors // 40 + 1)
      + (num_actors * 3)
      + (num_actors * 3)
  )

  print("\n" + "=" * 70)
  print(" EXECUTION SUMMARY")
  print("=" * 70)
  print(f"Total Threat Actors extracted      : {num_actors}")
  print(f"Total Associated Vulnerabilities   : {total_vulns}")
  print(f"Total API Calls made               : {client.call_count}")
  print(f"Estimated calls (Naive approach)   : ~{naive_calls}+ calls")
  if naive_calls > 0:
    savings = max(0, int((1 - client.call_count / naive_calls) * 100))
    print(f"API Call Reduction                 : ~{savings}% reduction")
  print(f"Elapsed Time                       : {elapsed:.2f}s")
  print(f"Output saved to                    : {args.output}")
  print("=" * 70)


if __name__ == "__main__":
  main()
