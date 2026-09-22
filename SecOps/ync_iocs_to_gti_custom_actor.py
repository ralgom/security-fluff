#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google Security Operations (SecOps) SOAR - Custom Action
Script Name: Sync IOCs to GTI Custom Threat Actor
Description: Extracts confirmed malicious entities (IPs, Domains, URLs, Hashes) from
             the case context, sanitizes private/internal infrastructure, and associates
             them with a Custom Threat Actor (Private Collection) in Google Threat
             Intelligence (GTI / VirusTotal Enterprise+ API v3).
Author: Google Cloud Security Specialists
Target Runtime: Google SecOps SOAR IDE (Python 3.x / Siemplify SDK)
"""

import ipaddress
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

import requests
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

# Constants
INTEGRATION_NAME = "GoogleThreatIntelligence"
GTI_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 25  # seconds

# Indicator type mappings according to GTI / VirusTotal API v3 schema
VT_TYPE_FILE = "file"
VT_TYPE_IP = "ip_address"
VT_TYPE_DOMAIN = "domain"
VT_TYPE_URL = "url"


class GTIClient:
    """HTTP Client for Google Threat Intelligence / VirusTotal v3 REST API."""

    def __init__(self, api_key: str, base_url: str = GTI_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Google-SecOps-SOAR-GTI-Sync/2.0"
        })

    def get_collection_by_name(self, collection_name: str) -> Optional[str]:
        """
        Searches for an existing collection by name within the customer's organization.
        Returns the collection ID if found, otherwise None.
        Prioritizes user-owned / editable collections of type 'collection'.
        """
        encoded_filter = urllib.parse.quote(f'name:"{collection_name}"')
        url = f"{self.base_url}/collections?filter={encoded_filter}"
        
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None
        
        results = response.json().get("data", [])
        # 1. First priority: look for IoC collection (collection_type == 'collection') matching name
        for item in results:
            attrs = item.get("attributes", {})
            col_type = attrs.get("collection_type") or item.get("type")
            if attrs.get("name", "").strip().lower() == collection_name.strip().lower():
                if col_type == "collection":
                    return item.get("id")

        # 2. Second priority: any matching threat entity (e.g. threat-actor)
        for item in results:
            attrs = item.get("attributes", {})
            if attrs.get("name", "").strip().lower() == collection_name.strip().lower():
                return item.get("id")
        return None

    def create_private_collection(
        self,
        name: str,
        description: str,
        tags: Optional[List[str]] = None,
        raw_items: Optional[List[str]] = None
    ) -> str:
        """
        Creates a new Private Collection representing the Custom Threat Actor in GTI.
        Ensures strict privacy isolation (private=True).
        """
        url = f"{self.base_url}/collections"
        collection_tags = ["custom-threat-actor", "secops-feedback"]
        if tags:
            collection_tags.extend(tags)
            
        attributes: Dict[str, Any] = {
            "name": name,
            "description": description,
            "private": True,  # In GTI OpenAPI spec, 'private': True enforces customer tenancy
            "tags": list(set(collection_tags))
        }
        if raw_items:
            attributes["raw_items"] = ", ".join(raw_items)

        payload = {
            "data": {
                "type": "collection",
                "attributes": attributes
            }
        }
        
        response = self.session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to create Private Collection in GTI: HTTP {response.status_code} - {response.text}"
            )
        
        return response.json()["data"]["id"]

    def add_indicators_to_collection(
        self,
        collection_id: str,
        ioc_items: List[Dict[str, str]]
    ) -> None:
        """
        Associates indicator items with the specified collection using official GTI v3 endpoints.
        Primary: POST /collections/{id}/{relationship}
                 where relationship is 'files', 'ip_addresses', 'domains', or 'urls'.
        Fallback: PATCH /collections/{id} with attributes.raw_items.
        """
        rel_map = {
            VT_TYPE_FILE: "files",
            VT_TYPE_IP: "ip_addresses",
            VT_TYPE_DOMAIN: "domains",
            VT_TYPE_URL: "urls",
        }

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        raw_values = []
        for item in ioc_items:
            itype = item.get("type")
            rel_name = rel_map.get(itype)
            raw_val = item.get("id") or item.get("url")
            if raw_val:
                raw_values.append(raw_val)
            if rel_name:
                grouped.setdefault(rel_name, []).append(item)

        errors = []
        success_count = 0
        for rel_name, items in grouped.items():
            url = f"{self.base_url}/collections/{collection_id}/{rel_name}"
            formatted_data = []
            for it in items:
                if it["type"] == VT_TYPE_URL:
                    formatted_data.append({"type": "url", "url": it.get("id")})
                else:
                    formatted_data.append({"type": it["type"], "id": it.get("id")})

            payload = {"data": formatted_data}
            response = self.session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if response.status_code in (200, 201, 204):
                success_count += 1
            else:
                errors.append(f"{rel_name} (HTTP {response.status_code}: {response.text})")

        # If any relationship POST failed or returned 404, fallback to PATCH /collections/{id} with raw_items
        if errors and raw_values:
            patch_url = f"{self.base_url}/collections/{collection_id}"
            patch_payload = {
                "data": {
                    "type": "collection",
                    "id": collection_id,
                    "attributes": {
                        "raw_items": ", ".join(raw_values)
                    }
                }
            }
            patch_resp = self.session.patch(patch_url, json=patch_payload, timeout=REQUEST_TIMEOUT)
            if patch_resp.status_code in (200, 204):
                return  # Fallback succeeded
            else:
                raise RuntimeError(
                    f"Failed to associate indicators with collection {collection_id}. "
                    f"Primary endpoint errors: {'; '.join(errors)}. "
                    f"PATCH raw_items fallback error: HTTP {patch_resp.status_code} - {patch_resp.text}"
                )
        elif errors:
            raise RuntimeError(
                f"Failed to associate indicators with collection {collection_id}: {'; '.join(errors)}"
            )


def is_private_or_internal_ip(ip_str: str) -> bool:
    """Verifies whether an IP address belongs to RFC 1918, loopback, link-local, or multicast."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return True  # Malformed strings are safely rejected


def is_internal_domain(domain_str: str) -> bool:
    """Filters typical internal enterprise DNS suffixes and unresolved hostnames."""
    domain_lower = domain_str.strip().lower()
    internal_suffixes = (
        ".local", ".internal", ".corp", ".lan", ".home",
        ".priv", ".domain", ".intranet", ".arpa"
    )
    if domain_lower.endswith(internal_suffixes) or "." not in domain_lower:
        return True
    return False


def extract_api_key(siemplify: SiemplifyAction) -> str:
    """
    Extracts the GTI API key from either:
    1. Action Parameter in the Playbook Block (e.g., 'GTI_API_Key', 'API Key', 'API_Key')
    2. Integration Instance Configuration (via extract_configuration_param)
    """
    # Check Action Parameters configured in the Playbook Block
    action_param_candidates = [
        "GTI_API_Key",
        "API Key",
        "API_Key",
        "GTI API Key",
        "GTI_ApiKey",
        "ApiKey"
    ]
    for candidate in action_param_candidates:
        try:
            val = siemplify.extract_action_param(
                param_name=candidate,
                is_mandatory=False,
                print_value=False
            )
            if val and str(val).strip():
                siemplify.LOGGER.info(f"Successfully loaded GTI API Key from Action Parameter '{candidate}'.")
                return str(val).strip()
        except Exception:
            pass

    # Check Integration Configuration parameters (global settings)
    provider_candidates = [
        INTEGRATION_NAME,
        "Google Threat Intelligence",
        "VirusTotal",
        "Custom Threat Intel Sync"
    ]
    config_param_candidates = ["API_Key", "API Key", "ApiKey", "GTI_API_Key"]
    for prov in provider_candidates:
        for param in config_param_candidates:
            try:
                val = siemplify.extract_configuration_param(
                    provider_name=prov,
                    param_name=param,
                    is_mandatory=False
                )
                if val and str(val).strip():
                    siemplify.LOGGER.info(f"Loaded GTI API Key from Integration '{prov}' Config '{param}'.")
                    return str(val).strip()
            except Exception:
                pass

    raise ValueError(
        "GTI API Key not found! Please ensure either:\n"
        "1. In the Playbook Block, you mapped an Action Parameter named 'GTI_API_Key' or 'API Key'.\n"
        "2. Or, under Settings > Integrations, you configured the Integration with parameter 'API_Key'."
    )


def normalize_and_filter_entities(
    entities: list
) -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """
    Parses and sanitizes SecOps target entities into GTI API v3 indicator structures.
    Returns:
        valid_items: list of dicts suitable for GTI payload
        included_log: list of strings describing added entities
        skipped_log: list of strings describing filtered entities
    """
    valid_items = []
    included_log = []
    skipped_log = []
    seen_identifiers = set()

    for entity in entities:
        e_type = str(getattr(entity, "entity_type", "")).upper()
        raw_val = str(getattr(entity, "identifier", "")).strip()
        
        if not raw_val or raw_val in seen_identifiers:
            continue
        seen_identifiers.add(raw_val)

        # 1. File Hashes (MD5, SHA1, SHA256)
        if e_type in ("FILEHASH", "MD5", "SHA1", "SHA256") or (
            e_type == "FILE" and re.match(r"^[a-fA-F0-9]{32,64}$", raw_val)
        ):
            hash_val = raw_val.lower()
            valid_items.append({"type": VT_TYPE_FILE, "id": hash_val})
            included_log.append(f"Hash: {hash_val}")

        # 2. IP Addresses (IPv4 / IPv6)
        elif e_type in ("ADDRESS", "IP", "DESTINATIONADDRESS", "SOURCEADDRESS"):
            if is_private_or_internal_ip(raw_val):
                skipped_log.append(f"IP (RFC1918/Private): {raw_val}")
            else:
                valid_items.append({"type": VT_TYPE_IP, "id": raw_val})
                included_log.append(f"External IP: {raw_val}")

        # 3. Hostnames / Domains
        elif e_type in ("HOSTNAME", "DOMAIN", "DESTINATIONHOSTNAME", "DESTINATIONFQDN"):
            if is_internal_domain(raw_val):
                skipped_log.append(f"Domain (Internal/Corp): {raw_val}")
            else:
                domain_val = raw_val.lower()
                valid_items.append({"type": VT_TYPE_DOMAIN, "id": domain_val})
                included_log.append(f"Domain: {domain_val}")

        # 4. URLs
        elif e_type in ("URL", "DESTINATIONURL", "REQUESTURL"):
            valid_items.append({"type": VT_TYPE_URL, "id": raw_val})
            included_log.append(f"URL: {raw_val}")

        else:
            skipped_log.append(f"Unsupported Entity Type [{e_type}]: {raw_val}")

    return valid_items, included_log, skipped_log


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Sync IOCs to GTI Custom Threat Actor"
    
    # 1. Extract API Key (supports Action Parameter from Playbook Block OR Integration Config)
    api_key = extract_api_key(siemplify)

    # 2. Extract Action Parameters from Playbook Block
    actor_name = siemplify.extract_action_param(
        param_name="Custom Threat Actor Name",
        is_mandatory=True,
        print_value=True
    ).strip()

    tlp_designation = siemplify.extract_action_param(
        param_name="TLP Designation",
        is_mandatory=False,
        default_value="TLP:AMBER",
        print_value=True
    ).strip()

    additional_tags_param = siemplify.extract_action_param(
        param_name="Additional Tags",
        is_mandatory=False,
        default_value="",
        print_value=False
    )
    
    custom_tags = [t.strip().lower() for t in additional_tags_param.split(",") if t.strip()]
    if tlp_designation:
        custom_tags.append(tlp_designation.lower().replace(":", "-"))

    case_id = getattr(siemplify, "case_id", "Manual-Trigger")

    # 3. Filter and Sanitize Entities
    target_entities = getattr(siemplify, "target_entities", [])
    valid_items, included_log, skipped_log = normalize_and_filter_entities(target_entities)

    if not valid_items:
        output_msg = (
            f"No eligible external IOCs found in case #{case_id} to sync.\n"
            f"Skipped items: {', '.join(skipped_log) if skipped_log else 'None'}"
        )
        siemplify.end(output_msg, False)
        return

    # 4. Initialize Client and Execute Sync
    client = GTIClient(api_key=api_key)
    
    try:
        # Check if collection already exists
        collection_id = client.get_collection_by_name(actor_name)
        if not collection_id:
            siemplify.LOGGER.info(f"Custom Threat Actor '{actor_name}' not found. Creating new Private Collection.")
            description = (
                f"Custom Threat Actor profile created via Google SecOps SOAR from Case #{case_id}. "
                f"Classification: {tlp_designation}."
            )
            collection_id = client.create_private_collection(
                name=actor_name,
                description=description,
                tags=custom_tags
            )
        else:
            siemplify.LOGGER.info(f"Resolved existing Custom Threat Actor '{actor_name}' (ID: {collection_id}).")

        # Push items to the collection
        client.add_indicators_to_collection(collection_id, valid_items)

        # 5. Build Output and Case Telemetry
        gti_portal_url = f"https://www.virustotal.com/gui/collection/{collection_id}"
        
        summary_lines = [
            f"Successfully synchronized {len(valid_items)} indicators to Custom Threat Actor '{actor_name}'.",
            f"GTI Workbench Collection: {gti_portal_url}",
            f"Included ({len(included_log)}): {'; '.join(included_log)}",
        ]
        if skipped_log:
            summary_lines.append(f"Sanitized/Skipped ({len(skipped_log)}): {'; '.join(skipped_log)}")

        final_msg = "\n".join(summary_lines)

        # Record audit trail in SecOps Case Notes
        siemplify.add_entity_comment(final_msg)
        
        # Output JSON result object for downstream playbook blocks
        result_json = {
            "status": "success",
            "threat_actor_name": actor_name,
            "collection_id": collection_id,
            "gti_url": gti_portal_url,
            "synced_ioc_count": len(valid_items),
            "synced_iocs": valid_items,
            "skipped_iocs": skipped_log
        }
        siemplify.result.add_result_json(result_json)
        siemplify.end(final_msg, True)

    except Exception as exc:
        err_msg = f"Error communicating with Google Threat Intelligence: {str(exc)}"
        siemplify.LOGGER.error(err_msg)
        siemplify.end(err_msg, False)


if __name__ == "__main__":
    main()
