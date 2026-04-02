"""
Automation MCP Server — Template-driven Meraki network provisioning.

Standalone MCP server that creates branch networks from YAML templates.
Calls the Meraki API directly (no upstream MCP dependencies).

Port: 3003
Auth: OAuth 2.0 + PKCE (same credentials as other MCP servers)
"""

import asyncio
import base64
import csv
import hashlib
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import meraki
import yaml
from aiohttp import web

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("automation-mcp")

# ──────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────
dashboard: Optional[meraki.DashboardAPI] = None
default_org_id: Optional[str] = None
templates: Dict[str, Any] = {}

NETWORK_REGISTRY_PATH = os.environ.get(
    "NETWORK_REGISTRY_PATH", "/app/data/network_registry.yaml"
)
TEMPLATE_DIR = os.environ.get("TEMPLATE_DIR", "/app/templates")

# ──────────────────────────────────────────────
# OAuth state
# ──────────────────────────────────────────────
TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", "/app/token_store.json")
valid_tokens: Dict[str, Dict] = {}
refresh_tokens: Dict[str, Dict] = {}
authorization_codes: Dict[str, Dict] = {}

# ──────────────────────────────────────────────
# Meraki init
# ──────────────────────────────────────────────

def initialize_meraki():
    global dashboard, default_org_id
    api_key = os.environ.get("MERAKI_API_KEY", "")
    if not api_key:
        logger.error("MERAKI_API_KEY not set")
        return
    dashboard = meraki.DashboardAPI(
        api_key,
        output_log=False,
        print_console=False,
        suppress_logging=True,
    )
    default_org_id = os.environ.get("MERAKI_ORG_ID", "")
    logger.info(f"Meraki API initialized (org: {default_org_id or 'auto'})")


# ──────────────────────────────────────────────
# Template loading
# ──────────────────────────────────────────────

def load_templates():
    """Load all YAML template files from the templates directory."""
    global templates
    templates = {}
    for fname in os.listdir(TEMPLATE_DIR):
        if fname.startswith("."):
            continue
        if fname.endswith((".yaml", ".yml")):
            path = os.path.join(TEMPLATE_DIR, fname)
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            template_name = os.path.splitext(fname)[0]
            templates[template_name] = data
            tiers = list(data.get("tiers", {}).keys())
            logger.info(f"Loaded template '{template_name}' with tiers: {tiers}")


def render_value(value: Any, variables: Dict[str, str]) -> Any:
    """Recursively substitute {var} placeholders in strings."""
    if isinstance(value, str):
        for key, val in variables.items():
            value = value.replace(f"{{{key}}}", str(val))
        return value
    if isinstance(value, dict):
        return {k: render_value(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render_value(item, variables) for item in value]
    return value


# ──────────────────────────────────────────────
# Network registry
# ──────────────────────────────────────────────

def load_registry() -> List[Dict]:
    """Load the master network registry."""
    if not os.path.exists(NETWORK_REGISTRY_PATH):
        return []
    with open(NETWORK_REGISTRY_PATH, "r") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, list) else []


def save_registry(entries: List[Dict]):
    """Save the master network registry."""
    os.makedirs(os.path.dirname(NETWORK_REGISTRY_PATH) or ".", exist_ok=True)
    with open(NETWORK_REGISTRY_PATH, "w") as f:
        yaml.dump(entries, f, default_flow_style=False, sort_keys=False)


def add_to_registry(entry: Dict):
    """Append a new network entry to the registry."""
    entries = load_registry()
    entries.append(entry)
    save_registry(entries)
    logger.info(f"Registry updated — {len(entries)} networks total")


# ──────────────────────────────────────────────
# Tool definitions
# ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "auto_list_templates",
        "description": (
            "List all available network provisioning templates and their tiers. "
            "Returns template names, tier names (small/medium/large), descriptions, "
            "and a summary of what each tier includes (VLANs, SSIDs, firewall rules)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "auto_create_branch_network",
        "description": (
            "Create a fully configured Meraki branch network from a template. "
            "Provisions the network, VLANs, SSIDs, firewall rules, and VPN in one call. "
            "Use 'dry_run: true' to preview what would be created without making changes. "
            "The network is automatically added to the master network registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Network name, e.g. '114 - Langley'",
                },
                "tier": {
                    "type": "string",
                    "enum": ["small", "medium", "large"],
                    "description": "Branch size tier — small (Corp+Guest), medium (+VoIP), large (+IoT)",
                },
                "template": {
                    "type": "string",
                    "description": "Template file name (default: 'branch')",
                    "default": "branch",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, preview the provisioning plan without creating anything",
                    "default": False,
                },
            },
            "required": ["name", "tier"],
        },
    },
    {
        "name": "auto_list_networks",
        "description": (
            "List all networks from the master network registry. "
            "Shows every network created through this automation tool, "
            "including site number, tier, creation date, and network ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "auto_get_network_config",
        "description": (
            "Get the full configuration of a managed network from the registry. "
            "Returns VLANs, SSIDs, firewall rules, VPN config, and tags. "
            "Use this to show the user what is currently configured before making changes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "network_name": {
                    "type": "string",
                    "description": "Network name or site number, e.g. '115 - Surrey' or '115'",
                },
            },
            "required": ["network_name"],
        },
    },
    {
        "name": "auto_update_branch_network",
        "description": (
            "Modify or delete an existing managed network. Supports adding/removing VLANs, "
            "enabling/disabling SSIDs, updating firewall rules, or deleting the entire network. "
            "Changes are applied to Meraki and the master registry is updated. "
            "Use 'dry_run: true' to preview changes without applying them. "
            "Set 'delete: true' to delete the network entirely from Meraki and the registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "network_name": {
                    "type": "string",
                    "description": "Network name or site number, e.g. '115 - Surrey' or '115'",
                },
                "add_vlans": {
                    "type": "array",
                    "description": "VLANs to add",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "description": "VLAN ID (e.g. 23)"},
                            "name": {"type": "string", "description": "VLAN name (e.g. 'Cameras')"},
                            "subnet": {"type": "string", "description": "Subnet CIDR (e.g. '10.0.115.23/24')"},
                            "appliance_ip": {"type": "string", "description": "Gateway IP (e.g. '10.0.115.23.1')"},
                        },
                        "required": ["id", "name", "subnet", "appliance_ip"],
                    },
                },
                "remove_vlans": {
                    "type": "array",
                    "description": "VLAN IDs to remove",
                    "items": {"type": "integer"},
                },
                "add_ssids": {
                    "type": "array",
                    "description": "SSIDs to configure (uses Meraki SSID slot number 0-14)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "number": {"type": "integer", "description": "SSID slot number (0-14)"},
                            "name": {"type": "string", "description": "SSID name"},
                            "enabled": {"type": "boolean", "default": True},
                            "auth_mode": {"type": "string", "default": "psk"},
                            "encryption_mode": {"type": "string", "default": "wpa"},
                            "psk": {"type": "string", "description": "Pre-shared key"},
                            "default_vlan_id": {"type": "integer", "description": "VLAN to map this SSID to"},
                        },
                        "required": ["number", "name"],
                    },
                },
                "disable_ssids": {
                    "type": "array",
                    "description": "SSID slot numbers to disable",
                    "items": {"type": "integer"},
                },
                "add_firewall_rules": {
                    "type": "array",
                    "description": "Firewall rules to add (appended before the default allow rule)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "comment": {"type": "string"},
                            "policy": {"type": "string", "enum": ["allow", "deny"]},
                            "protocol": {"type": "string", "default": "any"},
                            "src_cidr": {"type": "string", "default": "Any"},
                            "dest_cidr": {"type": "string", "default": "Any"},
                            "dest_port": {"type": "string", "default": "Any"},
                        },
                        "required": ["comment", "policy"],
                    },
                },
                "remove_firewall_rules": {
                    "type": "array",
                    "description": "Firewall rule comments to remove (matched by comment text)",
                    "items": {"type": "string"},
                },
                "add_tags": {
                    "type": "array",
                    "description": "Tags to add to the network (e.g. 'pilot', 'priority')",
                    "items": {"type": "string"},
                },
                "remove_tags": {
                    "type": "array",
                    "description": "Tags to remove from the network",
                    "items": {"type": "string"},
                },
                "delete": {
                    "type": "boolean",
                    "description": "If true, delete the entire network from Meraki and remove from registry",
                    "default": False,
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, preview changes without applying them",
                    "default": False,
                },
            },
            "required": ["network_name"],
        },
    },
    {
        "name": "auto_update_template",
        "description": (
            "Modify an existing provisioning template tier, or create a new template/tier. "
            "Changes are saved to the YAML template file. After saving, a propagation preview "
            "shows what would change on every existing site built from that template+tier. "
            "This tool does NOT modify any live sites — use auto_sync_template for that."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "description": "Template name (e.g. 'branch')",
                    "default": "branch",
                },
                "tier": {
                    "type": "string",
                    "description": "Tier name to modify or create (e.g. 'small', 'medium', 'large', or a new name)",
                },
                "description": {
                    "type": "string",
                    "description": "Tier description (required when creating a new tier)",
                },
                "add_vlans": {
                    "type": "array",
                    "description": "VLANs to add to the template tier",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "description": "VLAN ID"},
                            "name": {"type": "string", "description": "VLAN name"},
                            "subnet": {"type": "string", "description": "Subnet with template vars, e.g. '10.{site_high}.{site_low}.0/24'"},
                            "appliance_ip": {"type": "string", "description": "Gateway IP with template vars"},
                            "dhcp_handling": {"type": "string", "default": "Run a DHCP server"},
                            "dns_nameservers": {"type": "string", "default": "upstream_dns"},
                        },
                        "required": ["id", "name", "subnet", "appliance_ip"],
                    },
                },
                "remove_vlans": {
                    "type": "array",
                    "description": "VLAN IDs to remove from the template tier",
                    "items": {"type": "integer"},
                },
                "add_ssids": {
                    "type": "array",
                    "description": "SSIDs to add to the template tier",
                    "items": {
                        "type": "object",
                        "properties": {
                            "number": {"type": "integer", "description": "SSID slot number (0-14)"},
                            "name": {"type": "string", "description": "SSID name (can use {location} var)"},
                            "enabled": {"type": "boolean", "default": True},
                            "auth_mode": {"type": "string", "default": "psk"},
                            "encryption_mode": {"type": "string", "default": "wpa"},
                            "psk": {"type": "string", "description": "Pre-shared key"},
                            "ip_assignment_mode": {"type": "string", "default": "Bridge mode"},
                            "default_vlan_id": {"type": "integer", "description": "VLAN to map this SSID to"},
                        },
                        "required": ["number", "name"],
                    },
                },
                "remove_ssids": {
                    "type": "array",
                    "description": "SSID slot numbers to remove from the template tier",
                    "items": {"type": "integer"},
                },
                "add_firewall_rules": {
                    "type": "array",
                    "description": "Firewall rules to add to the template tier",
                    "items": {
                        "type": "object",
                        "properties": {
                            "comment": {"type": "string"},
                            "policy": {"type": "string", "enum": ["allow", "deny"]},
                            "protocol": {"type": "string", "default": "any"},
                            "src_cidr": {"type": "string", "default": "Any"},
                            "dest_cidr": {"type": "string", "default": "Any"},
                            "dest_port": {"type": "string", "default": "any"},
                            "syslog_enabled": {"type": "boolean", "default": False},
                        },
                        "required": ["comment", "policy"],
                    },
                },
                "remove_firewall_rules": {
                    "type": "array",
                    "description": "Firewall rule comments to remove from the template tier",
                    "items": {"type": "string"},
                },
                "set_vpn": {
                    "type": "object",
                    "description": "Replace VPN config for this tier",
                    "properties": {
                        "mode": {"type": "string", "enum": ["spoke", "hub", "none"]},
                        "hubs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "hub_id": {"type": "string"},
                                    "name": {"type": "string"},
                                    "use_default_route": {"type": "boolean", "default": False},
                                },
                                "required": ["hub_id"],
                            },
                        },
                        "subnets": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "local_subnet": {"type": "string"},
                                    "use_vpn": {"type": "boolean"},
                                },
                                "required": ["local_subnet", "use_vpn"],
                            },
                        },
                    },
                },
            },
            "required": ["template", "tier"],
        },
    },
    {
        "name": "auto_sync_template",
        "description": (
            "Propagate the current template definition to all existing sites built from it. "
            "Compares the template against each site's registry entry to determine what to "
            "add or remove, preserves site-specific customizations, and validates the "
            "'automated' tag before touching any site. "
            "Use 'dry_run: true' (default) to preview changes. Set 'dry_run: false' to apply. "
            "Optionally target a single site with 'network_name'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "description": "Template name (e.g. 'branch')",
                    "default": "branch",
                },
                "tier": {
                    "type": "string",
                    "description": "Tier name to sync (e.g. 'small', 'medium', 'large')",
                },
                "network_name": {
                    "type": "string",
                    "description": "Optional: sync only this specific site (name or site number). If omitted, syncs all matching sites.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true (default), preview changes without applying. Set false to apply.",
                    "default": True,
                },
            },
            "required": ["template", "tier"],
        },
    },
]

# ──────────────────────────────────────────────
# Tool: list_templates
# ──────────────────────────────────────────────

def tool_list_templates() -> str:
    result = {}
    for tpl_name, tpl_data in templates.items():
        tiers_summary = {}
        for tier_name, tier_cfg in tpl_data.get("tiers", {}).items():
            vlan_names = [v["name"] for v in tier_cfg.get("vlans", [])]
            ssid_count = len(tier_cfg.get("ssids", []))
            fw_count = len(tier_cfg.get("firewall_rules", []))
            vpn_mode = tier_cfg.get("vpn", {}).get("mode", "none")
            tiers_summary[tier_name] = {
                "description": tier_cfg.get("description", ""),
                "vlans": vlan_names,
                "ssid_count": ssid_count,
                "firewall_rule_count": fw_count,
                "vpn_mode": vpn_mode,
            }
        result[tpl_name] = {
            "product_types": tpl_data.get("product_types", []),
            "tiers": tiers_summary,
        }
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Tool: list_networks (registry)
# ──────────────────────────────────────────────

def tool_list_networks() -> str:
    entries = load_registry()
    if not entries:
        return json.dumps({"message": "No networks in registry yet.", "networks": []})

    # Enrich each entry with sync status
    enriched = []
    for entry in entries:
        e = dict(entry)
        tpl_name = e.get("template", "")
        tier_name = e.get("tier", "")
        tpl_data = templates.get(tpl_name, {})
        tier = tpl_data.get("tiers", {}).get(tier_name)

        if not tier:
            e["sync_status"] = "unknown"
            e["sync_detail"] = f"Template '{tpl_name}/{tier_name}' not found"
            enriched.append(e)
            continue

        # Compare template VLANs vs registry VLANs
        tpl_vlan_ids = {v["id"] for v in tier.get("vlans", [])}
        reg_vlan_ids = {v["id"] for v in e.get("vlans", [])}
        tpl_ssid_nums = {s["number"] for s in tier.get("ssids", [])}
        reg_ssid_nums = {s["number"] for s in e.get("ssids", [])}

        missing_vlans = tpl_vlan_ids - reg_vlan_ids
        extra_vlans = reg_vlan_ids - tpl_vlan_ids
        missing_ssids = tpl_ssid_nums - reg_ssid_nums
        extra_ssids = reg_ssid_nums - tpl_ssid_nums

        drift = []
        if missing_vlans:
            drift.append(f"Missing VLANs: {sorted(missing_vlans)}")
        if extra_vlans:
            drift.append(f"Extra VLANs (custom): {sorted(extra_vlans)}")
        if missing_ssids:
            drift.append(f"Missing SSIDs: {sorted(missing_ssids)}")
        if extra_ssids:
            drift.append(f"Extra SSIDs (custom): {sorted(extra_ssids)}")

        if not drift:
            e["sync_status"] = "in_sync"
        else:
            e["sync_status"] = "drift_detected"
            e["sync_drift"] = drift

        enriched.append(e)

    return json.dumps({"count": len(enriched), "networks": enriched}, indent=2)


# ──────────────────────────────────────────────
# Tool: create_branch_network
# ──────────────────────────────────────────────

def compute_site_octets(site_number: int) -> Dict[str, str]:
    """Convert a site number into two octets for IP addressing.

    site_number is split across the 2nd and 3rd octets:
      site 114  → high=0, low=114  → 10.0.114.0/24
      site 257  → high=1, low=1    → 10.1.1.0/24
      site 1500 → high=5, low=220  → 10.5.220.0/24

    VLAN offsets are added to the low octet:
      Corp (VLAN 10)  → low + 0
      VoIP (VLAN 30)  → low + 1
      IoT  (VLAN 40)  → low + 2

    Max supported site number: 65,279 (255 * 256 + 255 - 2 for offsets)
    """
    high = site_number // 256
    low = site_number % 256
    return {
        "site_high": str(high),
        "site_low": str(low),
        "site_low_voip": str(low + 1),
        "site_low_iot": str(low + 2),
        "site_low_mgmt": str(low + 3),
    }


def parse_network_name(name: str) -> Dict[str, str]:
    """Extract site_number and location from a name like '114 - Langley'.

    Produces variables for template rendering including two-octet IP fields.
    """
    match = re.match(r"(\d+)\s*-\s*(.+)", name.strip())
    if match:
        site_number = int(match.group(1))
        location = match.group(2).strip()
    else:
        # Fallback — no number prefix, generate from hash
        site_number = abs(hash(name)) % 900 + 100
        location = name.strip()

    octets = compute_site_octets(site_number)
    return {
        "site_number": str(site_number),
        "location": location,
        "name": name.strip(),
        **octets,
    }


def tool_create_branch_network(args: Dict) -> str:
    """Provision a branch network from template. Synchronous execution."""
    name = args.get("name", "")
    tier = args.get("tier", "small")
    template_name = args.get("template", "branch")
    dry_run = args.get("dry_run", False)

    # Validate inputs
    if not name:
        return json.dumps({"error": "Network name is required"})

    if template_name not in templates:
        return json.dumps({
            "error": f"Template '{template_name}' not found",
            "available": list(templates.keys()),
        })

    tpl = templates[template_name]
    tiers = tpl.get("tiers", {})

    if tier not in tiers:
        return json.dumps({
            "error": f"Tier '{tier}' not found in template '{template_name}'",
            "available": list(tiers.keys()),
        })

    tier_cfg = tiers[tier]
    variables = parse_network_name(name)
    product_types = tpl.get("product_types", ["appliance", "switch", "wireless"])

    # Render the tier config with variables
    rendered = render_value(tier_cfg, variables)

    # Build the provisioning plan
    plan = {
        "network_name": name,
        "tier": tier,
        "template": template_name,
        "tags": [f"{tier}_branch", "automated"],
        "site_number": variables["site_number"],
        "location": variables["location"],
        "product_types": product_types,
        "vlans": rendered.get("vlans", []),
        "ssids": rendered.get("ssids", []),
        "firewall_rules": rendered.get("firewall_rules", []),
        "vpn": rendered.get("vpn", {}),
    }

    if dry_run:
        return json.dumps({
            "mode": "dry_run",
            "message": "This is a preview — no changes were made.",
            "plan": plan,
        }, indent=2)

    # ── Execute provisioning ──
    if not dashboard:
        return json.dumps({"error": "Meraki API not initialized"})

    org_id = default_org_id
    if not org_id:
        return json.dumps({"error": "MERAKI_ORG_ID not configured"})

    log: List[Dict[str, Any]] = []
    network_id = None

    # Build tags: tier-based profile + "automated"
    network_tags = [f"{tier}_branch", "automated"]

    # Step 1: Create the network
    try:
        network = dashboard.organizations.createOrganizationNetwork(
            org_id,
            name=name,
            productTypes=product_types,
            tags=network_tags,
        )
        network_id = network["id"]
        log.append({
            "step": "create_network",
            "status": "success",
            "network_id": network_id,
            "tags": network_tags,
        })
        logger.info(f"Created network '{name}' ({network_id}) tags={network_tags}")
    except Exception as e:
        log.append({"step": "create_network", "status": "failed", "error": str(e)})
        return json.dumps({"status": "failed", "log": log}, indent=2)

    # Step 2: Enable VLANs on the appliance
    try:
        dashboard.appliance.updateNetworkApplianceVlansSettings(
            network_id, vlansEnabled=True
        )
        log.append({"step": "enable_vlans", "status": "success"})
    except Exception as e:
        log.append({"step": "enable_vlans", "status": "failed", "error": str(e)})

    # Step 3: Create VLANs
    for vlan_cfg in rendered.get("vlans", []):
        vlan_id = vlan_cfg["id"]
        try:
            dashboard.appliance.createNetworkApplianceVlan(
                network_id,
                id=str(vlan_id),
                name=vlan_cfg["name"],
                subnet=vlan_cfg["subnet"],
                applianceIp=vlan_cfg["appliance_ip"],
            )
            # Configure DHCP if specified
            dhcp_params = {}
            if vlan_cfg.get("dhcp_handling"):
                dhcp_params["dhcpHandling"] = vlan_cfg["dhcp_handling"]
            if vlan_cfg.get("dns_nameservers"):
                dhcp_params["dnsNameservers"] = vlan_cfg["dns_nameservers"]
            if dhcp_params:
                dashboard.appliance.updateNetworkApplianceVlan(
                    network_id, str(vlan_id), **dhcp_params
                )
            log.append({
                "step": f"create_vlan_{vlan_id}",
                "status": "success",
                "name": vlan_cfg["name"],
                "subnet": vlan_cfg["subnet"],
            })
            logger.info(f"  VLAN {vlan_id} ({vlan_cfg['name']}) created")
        except Exception as e:
            log.append({
                "step": f"create_vlan_{vlan_id}",
                "status": "failed",
                "error": str(e),
            })

    # Step 4: Delete default VLAN 1 (Meraki creates it automatically)
    try:
        dashboard.appliance.deleteNetworkApplianceVlan(network_id, "1")
        log.append({"step": "delete_default_vlan_1", "status": "success"})
    except Exception:
        # May not exist or may not be deletable — not critical
        log.append({"step": "delete_default_vlan_1", "status": "skipped"})

    # Step 5: Configure SSIDs
    for ssid_cfg in rendered.get("ssids", []):
        ssid_num = ssid_cfg["number"]
        try:
            params = {
                "name": ssid_cfg["name"],
                "enabled": ssid_cfg.get("enabled", True),
                "authMode": ssid_cfg.get("auth_mode", "psk"),
                "ipAssignmentMode": ssid_cfg.get("ip_assignment_mode", "Bridge mode"),
            }
            if ssid_cfg.get("default_vlan_id"):
                params["useVlanTagging"] = True
                params["defaultVlanId"] = ssid_cfg["default_vlan_id"]
            if ssid_cfg.get("encryption_mode"):
                params["encryptionMode"] = ssid_cfg["encryption_mode"]
            if ssid_cfg.get("psk"):
                params["psk"] = ssid_cfg["psk"]

            dashboard.wireless.updateNetworkWirelessSsid(
                network_id, str(ssid_num), **params
            )
            log.append({
                "step": f"configure_ssid_{ssid_num}",
                "status": "success",
                "name": ssid_cfg["name"],
                "vlan": ssid_cfg.get("default_vlan_id"),
            })
            logger.info(f"  SSID {ssid_num} ({ssid_cfg['name']}) configured")
        except Exception as e:
            log.append({
                "step": f"configure_ssid_{ssid_num}",
                "status": "failed",
                "error": str(e),
            })

    # Step 6: Configure firewall rules
    fw_rules = rendered.get("firewall_rules", [])
    if fw_rules:
        try:
            api_rules = []
            for rule in fw_rules:
                api_rules.append({
                    "comment": rule.get("comment", ""),
                    "policy": rule.get("policy", "deny"),
                    "protocol": rule.get("protocol", "any"),
                    "srcCidr": rule.get("src_cidr", "Any"),
                    "srcPort": rule.get("src_port", "Any"),
                    "destCidr": rule.get("dest_cidr", "Any"),
                    "destPort": rule.get("dest_port", "Any"),
                    "syslogEnabled": rule.get("syslog_enabled", False),
                })
            dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                network_id, rules=api_rules
            )
            log.append({
                "step": "configure_firewall",
                "status": "success",
                "rule_count": len(api_rules),
            })
            logger.info(f"  {len(api_rules)} firewall rules applied")
        except Exception as e:
            log.append({
                "step": "configure_firewall",
                "status": "failed",
                "error": str(e),
            })

    # Step 7: Configure site-to-site VPN
    vpn_cfg = rendered.get("vpn", {})
    if vpn_cfg.get("mode"):
        try:
            vpn_subnets = []
            for s in vpn_cfg.get("subnets", []):
                vpn_subnets.append({
                    "localSubnet": s["local_subnet"],
                    "useVpn": s["use_vpn"],
                })
            vpn_params = {
                "mode": vpn_cfg["mode"],
                "subnets": vpn_subnets,
            }
            # Configure hub(s) for spoke networks
            if vpn_cfg["mode"] == "spoke" and vpn_cfg.get("hubs"):
                vpn_params["hubs"] = [
                    {
                        "hubId": hub["hub_id"],
                        "useDefaultRoute": hub.get("use_default_route", False),
                    }
                    for hub in vpn_cfg["hubs"]
                ]
            dashboard.appliance.updateNetworkApplianceVpnSiteToSiteVpn(
                network_id, **vpn_params
            )
            hub_names = [h.get("name", h["hub_id"]) for h in vpn_cfg.get("hubs", [])]
            log.append({
                "step": "configure_vpn",
                "status": "success",
                "mode": vpn_cfg["mode"],
                "hubs": hub_names or "none",
                "subnet_count": len(vpn_subnets),
            })
            logger.info(f"  VPN configured as {vpn_cfg['mode']} → hubs: {hub_names}")
        except Exception as e:
            log.append({
                "step": "configure_vpn",
                "status": "failed",
                "error": str(e),
            })

    # ── Build result ──
    succeeded = sum(1 for s in log if s["status"] == "success")
    failed = sum(1 for s in log if s["status"] == "failed")
    status = "success" if failed == 0 else "partial" if succeeded > 0 else "failed"

    result = {
        "status": status,
        "network_name": name,
        "network_id": network_id,
        "tier": tier,
        "site_number": variables["site_number"],
        "location": variables["location"],
        "summary": {
            "steps_succeeded": succeeded,
            "steps_failed": failed,
        },
        "log": log,
    }

    # ── Add to registry ──
    if network_id:
        registry_entry = {
            "network_id": network_id,
            "name": name,
            "site_number": int(variables["site_number"]),
            "location": variables["location"],
            "tier": tier,
            "tags": network_tags,
            "template": template_name,
            "product_types": product_types,
            "vlans": [
                {"id": v["id"], "name": v["name"], "subnet": v["subnet"]}
                for v in rendered.get("vlans", [])
            ],
            "ssids": [
                {"number": s["number"], "name": s["name"]}
                for s in rendered.get("ssids", [])
            ],
            "vpn_mode": vpn_cfg.get("mode", "none"),
            "provisioned_at": datetime.now(timezone.utc).isoformat(),
            "provisioned_status": status,
        }
        add_to_registry(registry_entry)
        result["registry"] = "Network added to master registry"

    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Helper: find network in registry
# ──────────────────────────────────────────────

def find_registry_entry(network_name: str) -> Optional[Dict]:
    """Find a network in the registry by name or site number."""
    entries = load_registry()
    query = network_name.strip()
    for entry in entries:
        if entry["name"] == query:
            return entry
        if str(entry["site_number"]) == query:
            return entry
        # Partial match on location
        if query.lower() in entry.get("location", "").lower():
            return entry
    return None


def update_registry_entry(network_id: str, updates: Dict):
    """Update a specific network entry in the registry."""
    entries = load_registry()
    for entry in entries:
        if entry["network_id"] == network_id:
            entry.update(updates)
            entry["last_modified"] = datetime.now(timezone.utc).isoformat()
            break
    save_registry(entries)


# ──────────────────────────────────────────────
# Tool: get_network_config
# ──────────────────────────────────────────────

def tool_get_network_config(args: Dict) -> str:
    """Get full config for a managed network from registry + live Meraki data."""
    network_name = args.get("network_name", "")
    if not network_name:
        return json.dumps({"error": "network_name is required"})

    entry = find_registry_entry(network_name)
    if not entry:
        return json.dumps({
            "error": f"Network '{network_name}' not found in registry",
            "hint": "Use list_networks to see all managed networks",
        })

    network_id = entry["network_id"]

    # Pull live config from Meraki to supplement the registry
    live_data = {}
    if dashboard:
        try:
            vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
            live_data["vlans"] = [
                {
                    "id": v["id"],
                    "name": v["name"],
                    "subnet": v["subnet"],
                    "applianceIp": v["applianceIp"],
                    "dhcpHandling": v.get("dhcpHandling", ""),
                }
                for v in vlans
            ]
        except Exception:
            live_data["vlans"] = "could not fetch"

        try:
            ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
            live_data["ssids"] = [
                {
                    "number": s["number"],
                    "name": s["name"],
                    "enabled": s["enabled"],
                    "authMode": s.get("authMode", ""),
                    "defaultVlanId": s.get("defaultVlanId"),
                }
                for s in ssids
                if s.get("enabled") or s["number"] < 5
            ]
        except Exception:
            live_data["ssids"] = "could not fetch"

        try:
            fw = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
            live_data["firewall_rules"] = fw.get("rules", [])
        except Exception:
            live_data["firewall_rules"] = "could not fetch"

        try:
            vpn = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id)
            live_data["vpn"] = vpn
        except Exception:
            live_data["vpn"] = "could not fetch"

    result = {
        "registry": entry,
        "live_config": live_data if live_data else "Meraki API not available",
    }
    return json.dumps(result, indent=2, default=str)


# ──────────────────────────────────────────────
# Tool: update_branch_network
# ──────────────────────────────────────────────

def tool_update_branch_network(args: Dict) -> str:
    """Apply modifications to an existing managed network."""
    network_name = args.get("network_name", "")
    dry_run = args.get("dry_run", False)

    if not network_name:
        return json.dumps({"error": "network_name is required"})

    entry = find_registry_entry(network_name)
    if not entry:
        return json.dumps({
            "error": f"Network '{network_name}' not found in registry",
            "hint": "Use list_networks to see all managed networks",
        })

    network_id = entry["network_id"]
    delete = args.get("delete", False)
    log: List[Dict[str, Any]] = []

    # ── Delete network ──
    if delete:
        if dry_run:
            return json.dumps({
                "mode": "dry_run",
                "network": entry["name"],
                "network_id": network_id,
                "changes_planned": [f"DELETE network '{entry['name']}' from Meraki and registry"],
                "message": "Preview only — no changes were made.",
            }, indent=2)

        if not dashboard:
            return json.dumps({"error": "Meraki API not initialized"})

        try:
            dashboard.networks.deleteNetwork(network_id)
            log.append({"step": "delete_network", "status": "success", "network_id": network_id})
            logger.info(f"Deleted network '{entry['name']}' ({network_id})")
        except Exception as e:
            log.append({"step": "delete_network", "status": "failed", "error": str(e)})
            return json.dumps({"status": "failed", "log": log}, indent=2)

        # Remove from registry
        entries = load_registry()
        entries = [e for e in entries if e["network_id"] != network_id]
        save_registry(entries)
        logger.info(f"Removed '{entry['name']}' from registry — {len(entries)} networks remain")

        return json.dumps({
            "status": "success",
            "action": "deleted",
            "network": entry["name"],
            "network_id": network_id,
            "registry": f"Removed — {len(entries)} networks remain",
            "log": log,
        }, indent=2)

    # ── Modify network ──
    changes_planned = []

    add_vlans = args.get("add_vlans", [])
    remove_vlans = args.get("remove_vlans", [])
    add_ssids = args.get("add_ssids", [])
    disable_ssids = args.get("disable_ssids", [])
    add_fw_rules = args.get("add_firewall_rules", [])
    remove_fw_rules = args.get("remove_firewall_rules", [])
    add_tags = args.get("add_tags", [])
    remove_tags = args.get("remove_tags", [])

    # Build change summary
    for v in add_vlans:
        changes_planned.append(f"Add VLAN {v['id']} ({v['name']}) — {v['subnet']}")
    for vid in remove_vlans:
        changes_planned.append(f"Remove VLAN {vid}")
    for s in add_ssids:
        changes_planned.append(f"Configure SSID {s['number']} ({s['name']})")
    for snum in disable_ssids:
        changes_planned.append(f"Disable SSID {snum}")
    for r in add_fw_rules:
        changes_planned.append(f"Add firewall rule: {r.get('comment', 'unnamed')}")
    for rc in remove_fw_rules:
        changes_planned.append(f"Remove firewall rule: {rc}")
    for t in add_tags:
        changes_planned.append(f"Add tag: {t}")
    for t in remove_tags:
        changes_planned.append(f"Remove tag: {t}")

    if not changes_planned:
        return json.dumps({"error": "No changes specified"})

    if dry_run:
        return json.dumps({
            "mode": "dry_run",
            "network": entry["name"],
            "network_id": network_id,
            "changes_planned": changes_planned,
            "message": "Preview only — no changes were made.",
        }, indent=2)

    if not dashboard:
        return json.dumps({"error": "Meraki API not initialized"})

    # ── Apply VLAN additions ──
    for v in add_vlans:
        try:
            dashboard.appliance.createNetworkApplianceVlan(
                network_id,
                id=str(v["id"]),
                name=v["name"],
                subnet=v["subnet"],
                applianceIp=v["appliance_ip"],
            )
            log.append({
                "step": f"add_vlan_{v['id']}",
                "status": "success",
                "name": v["name"],
                "subnet": v["subnet"],
            })
            logger.info(f"  Added VLAN {v['id']} ({v['name']}) to {entry['name']}")
        except Exception as e:
            log.append({"step": f"add_vlan_{v['id']}", "status": "failed", "error": str(e)})

    # ��─ Apply VLAN removals ──
    for vid in remove_vlans:
        try:
            dashboard.appliance.deleteNetworkApplianceVlan(network_id, str(vid))
            log.append({"step": f"remove_vlan_{vid}", "status": "success"})
            logger.info(f"  Removed VLAN {vid} from {entry['name']}")
        except Exception as e:
            log.append({"step": f"remove_vlan_{vid}", "status": "failed", "error": str(e)})

    # ── Configure SSIDs ──
    for s in add_ssids:
        try:
            params = {
                "name": s["name"],
                "enabled": s.get("enabled", True),
                "authMode": s.get("auth_mode", "psk"),
                "ipAssignmentMode": s.get("ip_assignment_mode", "Bridge mode"),
            }
            if s.get("default_vlan_id"):
                params["useVlanTagging"] = True
                params["defaultVlanId"] = s["default_vlan_id"]
            if s.get("encryption_mode"):
                params["encryptionMode"] = s["encryption_mode"]
            if s.get("psk"):
                params["psk"] = s["psk"]

            dashboard.wireless.updateNetworkWirelessSsid(
                network_id, str(s["number"]), **params
            )
            log.append({
                "step": f"configure_ssid_{s['number']}",
                "status": "success",
                "name": s["name"],
            })
            logger.info(f"  Configured SSID {s['number']} ({s['name']}) on {entry['name']}")
        except Exception as e:
            log.append({"step": f"configure_ssid_{s['number']}", "status": "failed", "error": str(e)})

    # ── Disable SSIDs ──
    for snum in disable_ssids:
        try:
            dashboard.wireless.updateNetworkWirelessSsid(
                network_id, str(snum), enabled=False
            )
            log.append({"step": f"disable_ssid_{snum}", "status": "success"})
            logger.info(f"  Disabled SSID {snum} on {entry['name']}")
        except Exception as e:
            log.append({"step": f"disable_ssid_{snum}", "status": "failed", "error": str(e)})

    # ── Firewall rule changes ──
    if add_fw_rules or remove_fw_rules:
        try:
            # Fetch current rules
            current_fw = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
            current_rules = current_fw.get("rules", [])

            # Remove the default "allow any" rule (Meraki always appends it)
            custom_rules = [
                r for r in current_rules
                if r.get("comment") != "Default rule"
            ]

            # Remove rules by comment
            if remove_fw_rules:
                removed = []
                kept = []
                for r in custom_rules:
                    if r.get("comment", "") in remove_fw_rules:
                        removed.append(r.get("comment", ""))
                    else:
                        kept.append(r)
                custom_rules = kept
                for rc in removed:
                    log.append({"step": f"remove_fw_rule", "status": "success", "comment": rc})

            # Add new rules
            for rule in add_fw_rules:
                custom_rules.append({
                    "comment": rule.get("comment", ""),
                    "policy": rule.get("policy", "deny"),
                    "protocol": rule.get("protocol", "any"),
                    "srcCidr": rule.get("src_cidr", "Any"),
                    "srcPort": rule.get("src_port", "Any"),
                    "destCidr": rule.get("dest_cidr", "Any"),
                    "destPort": rule.get("dest_port", "Any"),
                    "syslogEnabled": rule.get("syslog_enabled", False),
                })
                log.append({
                    "step": "add_fw_rule",
                    "status": "success",
                    "comment": rule.get("comment", ""),
                })

            # Push updated ruleset
            dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                network_id, rules=custom_rules
            )
            logger.info(f"  Firewall rules updated on {entry['name']} ({len(custom_rules)} rules)")
        except Exception as e:
            log.append({"step": "update_firewall", "status": "failed", "error": str(e)})

    # ── Tag changes ──
    if add_tags or remove_tags:
        try:
            # Fetch current tags from Meraki
            net_info = dashboard.networks.getNetwork(network_id)
            current_tags = net_info.get("tags", [])

            # Apply removals then additions
            updated_tags = [t for t in current_tags if t not in remove_tags]
            for t in add_tags:
                if t not in updated_tags:
                    updated_tags.append(t)

            dashboard.networks.updateNetwork(network_id, tags=updated_tags)

            for t in remove_tags:
                if t in current_tags:
                    log.append({"step": f"remove_tag", "status": "success", "tag": t})
                else:
                    log.append({"step": f"remove_tag", "status": "skipped", "tag": t, "reason": "not present"})
            for t in add_tags:
                log.append({"step": f"add_tag", "status": "success", "tag": t})

            logger.info(f"  Tags updated on {entry['name']}: {updated_tags}")
        except Exception as e:
            log.append({"step": "update_tags", "status": "failed", "error": str(e)})

    # ── Update registry ──
    succeeded = sum(1 for s in log if s["status"] == "success")
    failed = sum(1 for s in log if s["status"] == "failed")
    status = "success" if failed == 0 else "partial" if succeeded > 0 else "failed"

    # Refresh VLAN and SSID lists in registry from live state
    registry_updates = {}
    try:
        live_vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
        registry_updates["vlans"] = [
            {"id": v["id"], "name": v["name"], "subnet": v["subnet"]}
            for v in live_vlans
        ]
    except Exception:
        pass

    try:
        live_ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
        registry_updates["ssids"] = [
            {"number": s["number"], "name": s["name"]}
            for s in live_ssids
            if s.get("enabled")
        ]
    except Exception:
        pass

    try:
        live_net = dashboard.networks.getNetwork(network_id)
        registry_updates["tags"] = live_net.get("tags", [])
    except Exception:
        pass

    if registry_updates:
        update_registry_entry(network_id, registry_updates)

    result = {
        "status": status,
        "network": entry["name"],
        "network_id": network_id,
        "summary": {
            "steps_succeeded": succeeded,
            "steps_failed": failed,
        },
        "log": log,
        "registry": "Updated" if registry_updates else "No update",
    }
    return json.dumps(result, indent=2, default=str)


# ──────────────────────────────────────────────
# Tool: update_template
# ──────────────────────────────────────────────

VALID_TEMPLATE_VARS = {
    "name", "location", "site_number",
    "site_high", "site_low", "site_low_voip", "site_low_iot", "site_low_mgmt",
}


def validate_template_ip(value: str, field_name: str) -> Optional[str]:
    """Validate that a subnet or IP template string will render to a valid address.

    Substitutes all known template variables with test values, then checks
    the result is a valid IPv4 address or CIDR.
    Returns an error message, or None if valid.
    """
    # Substitute template vars with realistic test values
    test_vars = {
        "name": "999 - Test", "location": "Test", "site_number": "999",
        "site_high": "3", "site_low": "231",
        "site_low_voip": "232", "site_low_iot": "233", "site_low_mgmt": "234",
    }
    rendered = value
    for k, v in test_vars.items():
        rendered = rendered.replace(f"{{{k}}}", v)

    # Check for unresolved variables
    if "{" in rendered or "}" in rendered:
        unknown = re.findall(r"\{(\w+)\}", rendered)
        return (
            f"{field_name}: unknown template variable(s): {unknown}. "
            f"Valid variables: {sorted(VALID_TEMPLATE_VARS)}"
        )

    # Strip CIDR prefix for IP validation
    ip_part = rendered.split("/")[0]
    octets = ip_part.split(".")
    if len(octets) != 4:
        return (
            f"{field_name}: '{value}' renders to '{rendered}' which has "
            f"{len(octets)} octets instead of 4"
        )
    for i, octet in enumerate(octets):
        try:
            n = int(octet)
            if n < 0 or n > 255:
                return f"{field_name}: '{value}' renders to '{rendered}' — octet {i+1} ({n}) is out of range"
        except ValueError:
            return f"{field_name}: '{value}' renders to '{rendered}' — octet {i+1} ('{octet}') is not a number"

    # Validate CIDR prefix if present
    if "/" in rendered:
        prefix = rendered.split("/")[1]
        try:
            p = int(prefix)
            if p < 0 or p > 32:
                return f"{field_name}: CIDR prefix /{prefix} is out of range (0-32)"
        except ValueError:
            return f"{field_name}: CIDR prefix '/{prefix}' is not a number"

    return None


def tool_update_template(args: Dict) -> str:
    """Modify a template tier and preview propagation impact on existing sites."""
    template_name = args.get("template", "branch")
    tier_name = args.get("tier", "")

    if not tier_name:
        return json.dumps({"error": "tier is required"})

    tpl_data = templates.get(template_name)
    creating_template = tpl_data is None
    creating_tier = False

    if creating_template:
        # New template — start from scratch
        tpl_data = {
            "product_types": ["appliance", "switch", "wireless"],
            "tiers": {},
        }
        creating_tier = True

    tiers = tpl_data.get("tiers", {})
    if tier_name not in tiers:
        creating_tier = True
        desc = args.get("description", "")
        if not desc:
            return json.dumps({
                "error": f"Tier '{tier_name}' does not exist in template '{template_name}'",
                "hint": "Provide a 'description' to create a new tier",
            })
        tiers[tier_name] = {
            "description": desc,
            "vlans": [],
            "ssids": [],
            "firewall_rules": [],
            "vpn": {},
        }

    tier = tiers[tier_name]

    # Snapshot the old tier state for diff
    old_vlan_ids = {v["id"] for v in tier.get("vlans", [])}
    old_ssid_nums = {s["number"] for s in tier.get("ssids", [])}
    old_fw_comments = {r.get("comment", "") for r in tier.get("firewall_rules", [])}
    old_vpn = tier.get("vpn", {})

    changes = []

    # ── Update description ──
    if args.get("description") and not creating_tier:
        old_desc = tier.get("description", "")
        tier["description"] = args["description"]
        changes.append(f"Description: '{old_desc}' -> '{args['description']}'")

    # ── Validate VLAN subnets/IPs before making any changes ──
    validation_errors = []
    for v in args.get("add_vlans", []):
        err = validate_template_ip(v["subnet"], f"VLAN {v['id']} subnet")
        if err:
            validation_errors.append(err)
        err = validate_template_ip(v["appliance_ip"], f"VLAN {v['id']} appliance_ip")
        if err:
            validation_errors.append(err)
    if validation_errors:
        return json.dumps({
            "error": "Template validation failed",
            "validation_errors": validation_errors,
            "hint": f"Valid template variables: {sorted(VALID_TEMPLATE_VARS)}",
        }, indent=2)

    # ── Add VLANs ──
    for v in args.get("add_vlans", []):
        existing = next((ev for ev in tier["vlans"] if ev["id"] == v["id"]), None)
        if existing:
            changes.append(f"Updated VLAN {v['id']} ({v['name']})")
            existing.update(v)
        else:
            tier["vlans"].append({
                "id": v["id"],
                "name": v["name"],
                "subnet": v["subnet"],
                "appliance_ip": v["appliance_ip"],
                "dhcp_handling": v.get("dhcp_handling", "Run a DHCP server"),
                "dns_nameservers": v.get("dns_nameservers", "upstream_dns"),
            })
            changes.append(f"Added VLAN {v['id']} ({v['name']}) — {v['subnet']}")

    # ── Remove VLANs ──
    for vid in args.get("remove_vlans", []):
        before = len(tier["vlans"])
        tier["vlans"] = [v for v in tier["vlans"] if v["id"] != vid]
        if len(tier["vlans"]) < before:
            changes.append(f"Removed VLAN {vid}")

    # ── Add SSIDs ──
    for s in args.get("add_ssids", []):
        existing = next((es for es in tier["ssids"] if es["number"] == s["number"]), None)
        if existing:
            changes.append(f"Updated SSID {s['number']} ({s['name']})")
            existing.update(s)
        else:
            ssid_entry = {
                "number": s["number"],
                "name": s["name"],
                "enabled": s.get("enabled", True),
                "auth_mode": s.get("auth_mode", "psk"),
                "encryption_mode": s.get("encryption_mode", "wpa"),
                "ip_assignment_mode": s.get("ip_assignment_mode", "Bridge mode"),
            }
            if s.get("psk"):
                ssid_entry["psk"] = s["psk"]
            if s.get("default_vlan_id"):
                ssid_entry["default_vlan_id"] = s["default_vlan_id"]
            tier["ssids"].append(ssid_entry)
            changes.append(f"Added SSID {s['number']} ({s['name']})")

    # ── Remove SSIDs ──
    for snum in args.get("remove_ssids", []):
        before = len(tier["ssids"])
        tier["ssids"] = [s for s in tier["ssids"] if s["number"] != snum]
        if len(tier["ssids"]) < before:
            changes.append(f"Removed SSID {snum}")

    # ── Add firewall rules ──
    for r in args.get("add_firewall_rules", []):
        tier["firewall_rules"].append({
            "comment": r.get("comment", ""),
            "policy": r.get("policy", "deny"),
            "protocol": r.get("protocol", "any"),
            "src_cidr": r.get("src_cidr", "Any"),
            "dest_cidr": r.get("dest_cidr", "Any"),
            "dest_port": r.get("dest_port", "any"),
            "syslog_enabled": r.get("syslog_enabled", False),
        })
        changes.append(f"Added firewall rule: {r.get('comment', '')}")

    # ── Remove firewall rules ──
    for comment in args.get("remove_firewall_rules", []):
        before = len(tier["firewall_rules"])
        tier["firewall_rules"] = [
            r for r in tier["firewall_rules"] if r.get("comment", "") != comment
        ]
        if len(tier["firewall_rules"]) < before:
            changes.append(f"Removed firewall rule: {comment}")

    # ── Set VPN ──
    if args.get("set_vpn") is not None:
        tier["vpn"] = args["set_vpn"]
        changes.append(f"Set VPN config: mode={args['set_vpn'].get('mode', 'none')}")

    if not changes and not creating_tier:
        return json.dumps({"error": "No changes specified"})

    if creating_tier:
        changes.insert(0, f"Created new tier '{tier_name}'")
    if creating_template:
        changes.insert(0, f"Created new template '{template_name}'")

    # ── Save the template ──
    tpl_data["tiers"][tier_name] = tier
    tpl_path = os.path.join(TEMPLATE_DIR, f"{template_name}.yaml")
    with open(tpl_path, "w") as f:
        yaml.dump(tpl_data, f, default_flow_style=False, sort_keys=False)

    # Reload into memory
    templates[template_name] = tpl_data
    logger.info(f"Template '{template_name}/{tier_name}' updated: {len(changes)} changes")

    # ── Compute propagation preview ──
    new_vlan_ids = {v["id"] for v in tier.get("vlans", [])}
    new_ssid_nums = {s["number"] for s in tier.get("ssids", [])}
    new_fw_comments = {r.get("comment", "") for r in tier.get("firewall_rules", [])}

    vlans_added = new_vlan_ids - old_vlan_ids
    vlans_removed = old_vlan_ids - new_vlan_ids
    ssids_added = new_ssid_nums - old_ssid_nums
    ssids_removed = old_ssid_nums - new_ssid_nums
    fw_added = new_fw_comments - old_fw_comments
    fw_removed = old_fw_comments - new_fw_comments
    vpn_changed = tier.get("vpn", {}) != old_vpn

    # Find all registry sites using this template+tier
    registry = load_registry()
    affected_sites = [
        e for e in registry
        if e.get("template") == template_name and e.get("tier") == tier_name
    ]

    propagation = []
    for site in affected_sites:
        site_changes = []
        site_vlan_ids = {v["id"] for v in site.get("vlans", [])}
        site_ssid_nums = {s["number"] for s in site.get("ssids", [])}

        # VLANs to add (in new template, not yet on site per registry)
        for vid in vlans_added:
            if vid not in site_vlan_ids:
                vlan_def = next(v for v in tier["vlans"] if v["id"] == vid)
                site_changes.append(f"Add VLAN {vid} ({vlan_def['name']})")

        # VLANs to remove (removed from template, exists on site per registry)
        for vid in vlans_removed:
            if vid in site_vlan_ids:
                site_changes.append(f"Remove VLAN {vid}")

        # SSIDs to add
        for snum in ssids_added:
            if snum not in site_ssid_nums:
                ssid_def = next(s for s in tier["ssids"] if s["number"] == snum)
                site_changes.append(f"Add SSID {snum} ({ssid_def['name']})")

        # SSIDs to remove
        for snum in ssids_removed:
            if snum in site_ssid_nums:
                site_changes.append(f"Disable SSID {snum}")

        # Firewall rules
        for comment in fw_added:
            site_changes.append(f"Add firewall rule: {comment}")
        for comment in fw_removed:
            site_changes.append(f"Remove firewall rule: {comment}")

        # VPN
        if vpn_changed:
            site_changes.append("Update VPN config")

        # Detect customizations (VLANs/SSIDs on site but not in OLD or NEW template)
        customizations = []
        all_template_vlan_ids = old_vlan_ids | new_vlan_ids
        for vid in site_vlan_ids:
            if vid not in all_template_vlan_ids:
                vlan_name = next(
                    (v["name"] for v in site.get("vlans", []) if v["id"] == vid), ""
                )
                customizations.append(f"Custom VLAN {vid} ({vlan_name}) — preserved")

        all_template_ssid_nums = old_ssid_nums | new_ssid_nums
        for snum in site_ssid_nums:
            if snum not in all_template_ssid_nums:
                ssid_name = next(
                    (s["name"] for s in site.get("ssids", []) if s["number"] == snum), ""
                )
                customizations.append(f"Custom SSID {snum} ({ssid_name}) — preserved")

        propagation.append({
            "site": site["name"],
            "network_id": site["network_id"],
            "changes": site_changes if site_changes else ["No changes needed"],
            "customizations": customizations if customizations else [],
        })

    result = {
        "status": "saved",
        "template": template_name,
        "tier": tier_name,
        "template_changes": changes,
        "template_state": {
            "vlans": len(tier.get("vlans", [])),
            "ssids": len(tier.get("ssids", [])),
            "firewall_rules": len(tier.get("firewall_rules", [])),
            "vpn_mode": tier.get("vpn", {}).get("mode", "none"),
        },
        "propagation_preview": {
            "affected_sites": len(affected_sites),
            "sites": propagation,
        },
        "next_step": (
            f"Use auto_sync_template with template='{template_name}' and tier='{tier_name}' "
            "to apply these changes to the affected sites."
            if affected_sites else "No existing sites to propagate to."
        ),
    }

    return json.dumps(result, indent=2, default=str)


# ──────────────────────────────────────────────
# Tool: sync_template
# ──────────────────────────────────────────────

def tool_sync_template(args: Dict) -> str:
    """Propagate current template to matching sites, preserving customizations."""
    template_name = args.get("template", "branch")
    tier_name = args.get("tier", "")
    target_name = args.get("network_name", "")
    dry_run = args.get("dry_run", True)

    if not tier_name:
        return json.dumps({"error": "tier is required"})

    tpl_data = templates.get(template_name)
    if not tpl_data:
        return json.dumps({"error": f"Template '{template_name}' not found"})

    tier = tpl_data.get("tiers", {}).get(tier_name)
    if not tier:
        return json.dumps({"error": f"Tier '{tier_name}' not found in template '{template_name}'"})

    if not dashboard:
        return json.dumps({"error": "Meraki API not initialized"})

    # Find matching sites in registry
    registry = load_registry()
    sites = [
        e for e in registry
        if e.get("template") == template_name and e.get("tier") == tier_name
    ]

    # Filter to single site if requested
    if target_name:
        query = target_name.strip()
        sites = [
            e for e in sites
            if e["name"] == query
            or str(e.get("site_number", "")) == query
            or query.lower() in e.get("location", "").lower()
        ]
        if not sites:
            return json.dumps({
                "error": f"No site matching '{target_name}' found in registry for {template_name}/{tier_name}",
            })

    if not sites:
        return json.dumps({
            "status": "no_sites",
            "message": f"No sites in registry use template '{template_name}' tier '{tier_name}'",
        })

    # Template-defined resources
    tpl_vlan_ids = {v["id"] for v in tier.get("vlans", [])}
    tpl_ssid_nums = {s["number"] for s in tier.get("ssids", [])}
    tpl_fw_comments = {r.get("comment", "") for r in tier.get("firewall_rules", [])}

    # Build rendered template config per-site (need site vars for subnet rendering)
    def render_tier_for_site(site_entry: Dict) -> Dict:
        """Render template tier with site-specific variables."""
        name = site_entry.get("name", "")
        site_number = site_entry.get("site_number", 0)
        location = site_entry.get("location", "")
        variables = {
            "name": name,
            "location": location,
            "site_number": str(site_number),
            "site_high": str(site_number // 256),
            "site_low": str(site_number % 256),
            "site_low_voip": str(site_number % 256 + 1),
            "site_low_iot": str(site_number % 256 + 2),
            "site_low_mgmt": str(site_number % 256 + 3),
        }
        return render_value(tier, variables)

    all_results = []

    for site in sites:
        network_id = site["network_id"]
        site_name = site["name"]
        site_log = []
        skipped = False

        # ── Safety check: verify 'automated' tag in Meraki ──
        try:
            live_net = dashboard.networks.getNetwork(network_id)
            live_tags = live_net.get("tags", [])
            if "automated" not in live_tags:
                all_results.append({
                    "site": site_name,
                    "network_id": network_id,
                    "status": "skipped",
                    "reason": f"Missing 'automated' tag (tags: {live_tags}). Site may be manually managed.",
                    "changes": [],
                    "customizations": [],
                })
                continue
        except Exception as e:
            all_results.append({
                "site": site_name,
                "network_id": network_id,
                "status": "error",
                "reason": f"Could not fetch network from Meraki: {e}",
                "changes": [],
                "customizations": [],
            })
            continue

        # ── Render template for this site ──
        rendered = render_tier_for_site(site)
        rendered_vlans = {v["id"]: v for v in rendered.get("vlans", [])}
        rendered_ssids = {s["number"]: s for s in rendered.get("ssids", [])}
        rendered_fw = rendered.get("firewall_rules", [])
        rendered_vpn = rendered.get("vpn", {})

        # ── Get live state from Meraki ──
        live_vlans = {}
        try:
            vlist = dashboard.appliance.getNetworkApplianceVlans(network_id)
            live_vlans = {v["id"]: v for v in vlist}
        except Exception as e:
            site_log.append({"step": "fetch_vlans", "status": "error", "error": str(e)})

        live_ssids = {}
        try:
            slist = dashboard.wireless.getNetworkWirelessSsids(network_id)
            live_ssids = {s["number"]: s for s in slist}
        except Exception as e:
            site_log.append({"step": "fetch_ssids", "status": "error", "error": str(e)})

        live_fw_rules = []
        try:
            fw = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
            live_fw_rules = [
                r for r in fw.get("rules", [])
                if r.get("comment") != "Default rule"
            ]
        except Exception as e:
            site_log.append({"step": "fetch_firewall", "status": "error", "error": str(e)})

        # Registry VLAN/SSID IDs (what template originally provisioned + synced)
        reg_vlan_ids = {v["id"] for v in site.get("vlans", [])}
        reg_ssid_nums = {s["number"] for s in site.get("ssids", [])}

        changes = []
        customizations = []

        # ── Detect customizations ──
        # VLANs in live state not in template (old or new)
        for vid, vdata in live_vlans.items():
            if vid not in tpl_vlan_ids and vid != 1:  # VLAN 1 is Meraki default
                customizations.append({
                    "type": "custom_vlan",
                    "vlan_id": vid,
                    "name": vdata.get("name", ""),
                    "action": "preserved",
                })

        # SSIDs enabled in live state not in template
        for snum, sdata in live_ssids.items():
            if sdata.get("enabled") and snum not in tpl_ssid_nums:
                customizations.append({
                    "type": "custom_ssid",
                    "ssid_number": snum,
                    "name": sdata.get("name", ""),
                    "action": "preserved",
                })

        # Custom firewall rules (comments not in template)
        live_fw_comments = {r.get("comment", "") for r in live_fw_rules}
        for comment in live_fw_comments:
            if comment and comment not in tpl_fw_comments:
                customizations.append({
                    "type": "custom_firewall_rule",
                    "comment": comment,
                    "action": "preserved",
                })

        # ── Compute changes: VLANs ──
        # Add VLANs in template but not live
        for vid, vdef in rendered_vlans.items():
            if vid not in live_vlans:
                changes.append({
                    "action": "add_vlan",
                    "vlan_id": vid,
                    "name": vdef["name"],
                    "subnet": vdef.get("subnet", ""),
                })

        # Remove VLANs that were in old registry (template-managed) but removed from template
        for vid in reg_vlan_ids:
            if vid not in tpl_vlan_ids and vid in live_vlans:
                changes.append({
                    "action": "remove_vlan",
                    "vlan_id": vid,
                    "name": live_vlans[vid].get("name", ""),
                })

        # Update VLANs that are in both template and live but have different subnets
        for vid, vdef in rendered_vlans.items():
            if vid in live_vlans:
                live_subnet = live_vlans[vid].get("subnet", "")
                tpl_subnet = vdef.get("subnet", "")
                if tpl_subnet and live_subnet and tpl_subnet != live_subnet:
                    changes.append({
                        "action": "update_vlan",
                        "vlan_id": vid,
                        "name": vdef["name"],
                        "old_subnet": live_subnet,
                        "new_subnet": tpl_subnet,
                    })

        # ── Compute changes: SSIDs ──
        for snum, sdef in rendered_ssids.items():
            live_ssid = live_ssids.get(snum, {})
            if not live_ssid.get("enabled") and sdef.get("enabled", True):
                changes.append({
                    "action": "enable_ssid",
                    "ssid_number": snum,
                    "name": sdef["name"],
                })
            elif live_ssid.get("name") != sdef["name"] and sdef.get("enabled", True):
                changes.append({
                    "action": "update_ssid",
                    "ssid_number": snum,
                    "old_name": live_ssid.get("name", ""),
                    "new_name": sdef["name"],
                })

        # Disable SSIDs removed from template but still enabled
        for snum in reg_ssid_nums:
            if snum not in tpl_ssid_nums:
                live_ssid = live_ssids.get(snum, {})
                if live_ssid.get("enabled"):
                    changes.append({
                        "action": "disable_ssid",
                        "ssid_number": snum,
                        "name": live_ssid.get("name", ""),
                    })

        # ── Compute changes: Firewall rules ──
        # Add template rules not in live
        for rule in rendered_fw:
            comment = rule.get("comment", "")
            if comment not in live_fw_comments:
                changes.append({
                    "action": "add_firewall_rule",
                    "comment": comment,
                    "policy": rule.get("policy", ""),
                })

        # Remove rules that were template-managed but removed from template
        old_tpl_fw = {r.get("comment", "") for r in site.get("firewall_rules", [])} if "firewall_rules" in site else set()
        for comment in old_tpl_fw:
            if comment and comment not in tpl_fw_comments and comment in live_fw_comments:
                changes.append({
                    "action": "remove_firewall_rule",
                    "comment": comment,
                })

        if not changes:
            all_results.append({
                "site": site_name,
                "network_id": network_id,
                "status": "in_sync",
                "changes": [],
                "customizations": customizations,
                "log": site_log,
            })
            continue

        # ── Dry run: just report ──
        if dry_run:
            all_results.append({
                "site": site_name,
                "network_id": network_id,
                "status": "changes_pending",
                "changes": changes,
                "customizations": customizations,
            })
            continue

        # ── Apply changes ──
        for change in changes:
            action = change["action"]

            if action == "add_vlan":
                try:
                    vdef = rendered_vlans[change["vlan_id"]]
                    dashboard.appliance.createNetworkApplianceVlan(
                        network_id,
                        id=str(change["vlan_id"]),
                        name=vdef["name"],
                        subnet=vdef.get("subnet", ""),
                        applianceIp=vdef.get("appliance_ip", ""),
                    )
                    # Set DHCP if specified
                    dhcp = vdef.get("dhcp_handling")
                    if dhcp:
                        dashboard.appliance.updateNetworkApplianceVlan(
                            network_id, str(change["vlan_id"]),
                            dhcpHandling=dhcp,
                            dnsNameservers=vdef.get("dns_nameservers", "upstream_dns"),
                        )
                    site_log.append({"step": f"add_vlan_{change['vlan_id']}", "status": "success"})
                    logger.info(f"  [{site_name}] Added VLAN {change['vlan_id']} ({vdef['name']})")
                except Exception as e:
                    site_log.append({"step": f"add_vlan_{change['vlan_id']}", "status": "failed", "error": str(e)})

            elif action == "remove_vlan":
                try:
                    dashboard.appliance.deleteNetworkApplianceVlan(network_id, str(change["vlan_id"]))
                    site_log.append({"step": f"remove_vlan_{change['vlan_id']}", "status": "success"})
                    logger.info(f"  [{site_name}] Removed VLAN {change['vlan_id']}")
                except Exception as e:
                    site_log.append({"step": f"remove_vlan_{change['vlan_id']}", "status": "failed", "error": str(e)})

            elif action == "update_vlan":
                try:
                    vdef = rendered_vlans[change["vlan_id"]]
                    dashboard.appliance.updateNetworkApplianceVlan(
                        network_id, str(change["vlan_id"]),
                        subnet=vdef.get("subnet", ""),
                        applianceIp=vdef.get("appliance_ip", ""),
                    )
                    site_log.append({"step": f"update_vlan_{change['vlan_id']}", "status": "success"})
                    logger.info(f"  [{site_name}] Updated VLAN {change['vlan_id']} subnet")
                except Exception as e:
                    site_log.append({"step": f"update_vlan_{change['vlan_id']}", "status": "failed", "error": str(e)})

            elif action == "enable_ssid" or action == "update_ssid":
                try:
                    sdef = rendered_ssids[change.get("ssid_number")]
                    params = {
                        "name": sdef["name"],
                        "enabled": True,
                        "authMode": sdef.get("auth_mode", "psk"),
                        "ipAssignmentMode": sdef.get("ip_assignment_mode", "Bridge mode"),
                    }
                    if sdef.get("encryption_mode"):
                        params["encryptionMode"] = sdef["encryption_mode"]
                    if sdef.get("psk"):
                        params["psk"] = sdef["psk"]
                    if sdef.get("default_vlan_id"):
                        params["useVlanTagging"] = True
                        params["defaultVlanId"] = sdef["default_vlan_id"]
                    dashboard.wireless.updateNetworkWirelessSsid(
                        network_id, str(change["ssid_number"]), **params
                    )
                    site_log.append({"step": f"{action}_{change['ssid_number']}", "status": "success"})
                    logger.info(f"  [{site_name}] {action} SSID {change['ssid_number']}")
                except Exception as e:
                    site_log.append({"step": f"{action}_{change['ssid_number']}", "status": "failed", "error": str(e)})

            elif action == "disable_ssid":
                try:
                    dashboard.wireless.updateNetworkWirelessSsid(
                        network_id, str(change["ssid_number"]), enabled=False
                    )
                    site_log.append({"step": f"disable_ssid_{change['ssid_number']}", "status": "success"})
                    logger.info(f"  [{site_name}] Disabled SSID {change['ssid_number']}")
                except Exception as e:
                    site_log.append({"step": f"disable_ssid_{change['ssid_number']}", "status": "failed", "error": str(e)})

            elif action == "add_firewall_rule" or action == "remove_firewall_rule":
                pass  # Handled in batch below

        # ── Batch firewall rule update ──
        fw_adds = [c for c in changes if c["action"] == "add_firewall_rule"]
        fw_removes = {c["comment"] for c in changes if c["action"] == "remove_firewall_rule"}

        if fw_adds or fw_removes:
            try:
                # Start from current live rules
                updated_rules = [r for r in live_fw_rules if r.get("comment", "") not in fw_removes]

                # Add new template rules
                for rule in rendered_fw:
                    comment = rule.get("comment", "")
                    if comment in {c["comment"] for c in fw_adds}:
                        updated_rules.append({
                            "comment": rule.get("comment", ""),
                            "policy": rule.get("policy", "deny"),
                            "protocol": rule.get("protocol", "any"),
                            "srcCidr": rule.get("src_cidr", "Any"),
                            "srcPort": rule.get("src_port", "Any"),
                            "destCidr": rule.get("dest_cidr", "Any"),
                            "destPort": rule.get("dest_port", "any"),
                            "syslogEnabled": rule.get("syslog_enabled", False),
                        })

                dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                    network_id, rules=updated_rules
                )
                site_log.append({"step": "update_firewall", "status": "success",
                                 "added": len(fw_adds), "removed": len(fw_removes)})
                logger.info(f"  [{site_name}] Firewall rules updated (+{len(fw_adds)} -{len(fw_removes)})")
            except Exception as e:
                site_log.append({"step": "update_firewall", "status": "failed", "error": str(e)})

        # ── Refresh registry from live state ──
        registry_updates = {}
        try:
            refreshed_vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
            registry_updates["vlans"] = [
                {"id": v["id"], "name": v["name"], "subnet": v["subnet"]}
                for v in refreshed_vlans
            ]
        except Exception:
            pass
        try:
            refreshed_ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
            registry_updates["ssids"] = [
                {"number": s["number"], "name": s["name"]}
                for s in refreshed_ssids if s.get("enabled")
            ]
        except Exception:
            pass

        registry_updates["last_synced_template"] = datetime.now(timezone.utc).isoformat()
        update_registry_entry(network_id, registry_updates)

        succeeded = sum(1 for s in site_log if s.get("status") == "success")
        failed = sum(1 for s in site_log if s.get("status") == "failed")
        status = "success" if failed == 0 else "partial" if succeeded > 0 else "failed"

        all_results.append({
            "site": site_name,
            "network_id": network_id,
            "status": status,
            "changes": changes,
            "customizations": customizations,
            "log": site_log,
            "summary": {"succeeded": succeeded, "failed": failed},
        })

    # ── Build final output ──
    total_sites = len(all_results)
    synced = sum(1 for r in all_results if r["status"] == "success")
    in_sync = sum(1 for r in all_results if r["status"] == "in_sync")
    skipped_count = sum(1 for r in all_results if r["status"] == "skipped")
    pending = sum(1 for r in all_results if r["status"] == "changes_pending")
    errors = sum(1 for r in all_results if r["status"] in ("failed", "error", "partial"))

    result = {
        "mode": "dry_run" if dry_run else "applied",
        "template": template_name,
        "tier": tier_name,
        "summary": {
            "total_sites": total_sites,
            "synced": synced,
            "already_in_sync": in_sync,
            "changes_pending": pending,
            "skipped": skipped_count,
            "errors": errors,
        },
        "sites": all_results,
    }

    if dry_run and pending > 0:
        result["next_step"] = (
            f"Run auto_sync_template with template='{template_name}', tier='{tier_name}', "
            "dry_run=false to apply these changes."
        )

    return json.dumps(result, indent=2, default=str)


# ──────────────────────────────────────────────
# Tool dispatcher
# ──────────────────────────────────────────────

def execute_tool(name: str, args: Dict) -> str:
    if name == "auto_list_templates":
        return tool_list_templates()
    elif name == "auto_create_branch_network":
        return tool_create_branch_network(args)
    elif name == "auto_list_networks":
        return tool_list_networks()
    elif name == "auto_get_network_config":
        return tool_get_network_config(args)
    elif name == "auto_update_branch_network":
        return tool_update_branch_network(args)
    elif name == "auto_update_template":
        return tool_update_template(args)
    elif name == "auto_sync_template":
        return tool_sync_template(args)
    else:
        return json.dumps({"error": f"Unknown tool: {name}"})


# ══════════════════════════════════════════════
# OAuth 2.0 + PKCE  (identical pattern to other MCP servers)
# ══════════════════════════════════════════════

def load_tokens():
    global valid_tokens, refresh_tokens
    try:
        if os.path.exists(TOKEN_STORE_PATH):
            with open(TOKEN_STORE_PATH, "r") as f:
                data = json.load(f)
            now = time.time()
            valid_tokens = {
                t: meta for t, meta in data.get("access_tokens", {}).items()
                if meta.get("expires", 0) > now
            }
            refresh_tokens = {
                t: meta for t, meta in data.get("refresh_tokens", {}).items()
                if meta.get("expires", 0) > now
            }
            logger.info(
                f"Loaded {len(valid_tokens)} access tokens, "
                f"{len(refresh_tokens)} refresh tokens from storage"
            )
    except Exception as e:
        logger.warning(f"Could not load token store: {e}")


def save_tokens():
    try:
        os.makedirs(os.path.dirname(TOKEN_STORE_PATH) or ".", exist_ok=True)
        data = {
            "access_tokens": valid_tokens,
            "refresh_tokens": refresh_tokens,
        }
        with open(TOKEN_STORE_PATH, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning(f"Could not save token store: {e}")


def generate_access_token() -> str:
    return secrets.token_hex(32)


def generate_refresh_token() -> str:
    return secrets.token_hex(48)


def generate_authorization_code() -> str:
    return secrets.token_urlsafe(32)


def validate_client_id(client_id: str) -> bool:
    expected = os.environ.get("OAUTH_CLIENT_ID", "")
    if not expected:
        return False
    return secrets.compare_digest(client_id, expected)


def is_oauth_enabled() -> bool:
    return bool(os.environ.get("OAUTH_CLIENT_ID"))


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, code_challenge)
    elif method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    return False


def get_server_url(request: web.Request) -> str:
    proto = request.headers.get("X-Forwarded-Proto", "http")
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}"


# ──────────────────────────────────────────────
# OAuth endpoints
# ──────────────────────────────────────────────

async def handle_protected_resource_metadata(request: web.Request) -> web.Response:
    server_url = get_server_url(request)
    return web.json_response({
        "resource": server_url,
        "authorization_servers": [server_url],
        "bearer_methods_supported": ["header"],
    })


async def handle_oauth_metadata(request: web.Request) -> web.Response:
    server_url = get_server_url(request)
    return web.json_response({
        "issuer": server_url,
        "authorization_endpoint": f"{server_url}/authorize",
        "token_endpoint": f"{server_url}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    })


async def handle_authorize(request: web.Request) -> web.Response:
    try:
        response_type = request.query.get("response_type", "")
        client_id = request.query.get("client_id", "")
        redirect_uri = request.query.get("redirect_uri", "")
        code_challenge = request.query.get("code_challenge", "")
        code_challenge_method = request.query.get("code_challenge_method", "S256")
        state = request.query.get("state", "")

        if response_type != "code":
            return web.json_response(
                {"error": "unsupported_response_type"}, status=400
            )
        if not validate_client_id(client_id):
            return web.json_response({"error": "invalid_client"}, status=401)
        if not redirect_uri:
            return web.json_response(
                {"error": "invalid_request", "error_description": "redirect_uri required"},
                status=400,
            )
        if not code_challenge:
            return web.json_response(
                {"error": "invalid_request", "error_description": "code_challenge required"},
                status=400,
            )

        code = generate_authorization_code()
        authorization_codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires": time.time() + 600,
        }

        redirect_params = {"code": code}
        if state:
            redirect_params["state"] = state

        separator = "&" if "?" in redirect_uri else "?"
        raise web.HTTPFound(
            location=f"{redirect_uri}{separator}{urlencode(redirect_params)}"
        )

    except web.HTTPFound:
        raise
    except Exception as e:
        logger.error(f"Authorization error: {e}")
        return web.json_response({"error": "server_error", "error_description": str(e)}, status=500)


async def handle_oauth_token(request: web.Request) -> web.Response:
    try:
        content_type = request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            data = await request.post()
        elif "application/json" in content_type:
            data = await request.json()
        else:
            return web.json_response({"error": "invalid_request"}, status=400)

        grant_type = data.get("grant_type", "")
        client_id = data.get("client_id", "")

        if grant_type not in ("authorization_code", "refresh_token"):
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

        if grant_type == "authorization_code":
            code = data.get("code", "")
            redirect_uri = data.get("redirect_uri", "")
            code_verifier = data.get("code_verifier", "")

            if code not in authorization_codes:
                return web.json_response({"error": "invalid_grant"}, status=400)

            code_data = authorization_codes[code]

            if time.time() > code_data["expires"]:
                del authorization_codes[code]
                return web.json_response({"error": "invalid_grant"}, status=400)
            if not secrets.compare_digest(client_id, code_data["client_id"]):
                return web.json_response({"error": "invalid_grant"}, status=400)
            if not secrets.compare_digest(redirect_uri, code_data["redirect_uri"]):
                return web.json_response({"error": "invalid_grant"}, status=400)
            if not verify_pkce(
                code_verifier, code_data["code_challenge"], code_data["code_challenge_method"]
            ):
                return web.json_response({"error": "invalid_grant"}, status=400)

            del authorization_codes[code]

        elif grant_type == "refresh_token":
            incoming = data.get("refresh_token", "")
            if not incoming or incoming not in refresh_tokens:
                return web.json_response({"error": "invalid_grant"}, status=400)
            rt_data = refresh_tokens[incoming]
            if time.time() > rt_data["expires"]:
                del refresh_tokens[incoming]
                save_tokens()
                return web.json_response({"error": "invalid_grant"}, status=400)
            del refresh_tokens[incoming]

        access_token = generate_access_token()
        new_refresh = generate_refresh_token()
        valid_tokens[access_token] = {"expires": time.time() + 86400}
        refresh_tokens[new_refresh] = {
            "client_id": client_id,
            "expires": time.time() + 7776000,
        }
        save_tokens()

        logger.info(f"Token issued via {grant_type}")
        return web.json_response({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": new_refresh,
        })

    except Exception as e:
        logger.error(f"Token error: {e}")
        return web.json_response({"error": "server_error"}, status=500)


# ──────────────────────────────────────────────
# MCP request handler
# ──────────────────────────────────────────────

async def handle_mcp_request(request: web.Request) -> web.Response:
    # Bearer token check
    if is_oauth_enabled():
        server_url = get_server_url(request)
        resource_url = f"{server_url}/.well-known/oauth-protected-resource"
        www_auth = f'Bearer resource_metadata="{resource_url}"'

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Unauthorized"}},
                status=401,
                headers={"WWW-Authenticate": www_auth},
            )
        token = auth_header[7:]
        token_meta = valid_tokens.get(token)
        if not token_meta or token_meta["expires"] < time.time():
            if token_meta:
                del valid_tokens[token]
                save_tokens()
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Unauthorized"}},
                status=401,
                headers={"WWW-Authenticate": www_auth},
            )

    try:
        body = await request.json()
    except Exception:
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status=400,
        )

    method = body.get("method", "")
    params = body.get("params", {})
    rpc_id = body.get("id")

    if method == "initialize":
        return web.json_response({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "automation-mcp",
                    "version": "1.0.0",
                },
            },
        })

    if method == "notifications/initialized":
        return web.json_response({"jsonrpc": "2.0", "id": rpc_id, "result": {}})

    if method == "tools/list":
        return web.json_response({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"tools": TOOLS},
        })

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        # Strip n8n metadata keys
        filtered = {
            k: v for k, v in arguments.items()
            if k not in ("sessionId", "action", "chatInput", "toolCallId")
        }

        try:
            result_text = execute_tool(tool_name, filtered)
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            result_text = json.dumps({"error": str(e)})

        return web.json_response({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"content": [{"type": "text", "text": result_text}]},
        })

    return web.json_response({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    })


# ──────────────────────────────────────────────
# Utility endpoints
# ──────────────────────────────────────────────

async def health_check(request: web.Request) -> web.Response:
    return web.json_response({
        "status": "healthy",
        "service": "automation-mcp",
        "version": "1.0.0",
        "meraki_connected": dashboard is not None,
        "templates_loaded": list(templates.keys()),
        "registry_count": len(load_registry()),
    })


async def list_tools_endpoint(request: web.Request) -> web.Response:
    return web.json_response({"tools": [t["name"] for t in TOOLS]})


# ──────────────────────────────────────────────
# Dashboard — read-only web UI
# ──────────────────────────────────────────────

async def handle_api_registry(request: web.Request) -> web.Response:
    """Return the network registry as JSON."""
    return web.json_response(load_registry())


async def handle_api_templates(request: web.Request) -> web.Response:
    """Return loaded templates as JSON (strip PSK secrets)."""
    sanitized = {}
    for tpl_name, tpl_data in templates.items():
        sanitized[tpl_name] = {
            "product_types": tpl_data.get("product_types", []),
            "tiers": {},
        }
        for tier_name, tier_cfg in tpl_data.get("tiers", {}).items():
            tier_copy = {
                "description": tier_cfg.get("description", ""),
                "vlans": tier_cfg.get("vlans", []),
                "ssids": [],
                "firewall_rules": tier_cfg.get("firewall_rules", []),
                "vpn": tier_cfg.get("vpn", {}),
            }
            for ssid in tier_cfg.get("ssids", []):
                s = dict(ssid)
                if "psk" in s:
                    s["psk"] = "********"
                tier_copy["ssids"].append(s)
            sanitized[tpl_name]["tiers"][tier_name] = tier_copy
    return web.json_response(sanitized)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Automation MCP Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #232733;
    --border: #2e3345;
    --text: #e1e4ed;
    --text2: #8b91a5;
    --accent: #6c8cff;
    --accent2: #4a6adf;
    --green: #34d399;
    --red: #f87171;
    --orange: #fbbf24;
    --tag-bg: #2a2f40;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  h1 {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }
  .subtitle {
    color: var(--text2);
    font-size: 0.875rem;
    margin-bottom: 2rem;
  }
  .tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1.5rem;
  }
  .tab {
    padding: 0.75rem 1.25rem;
    cursor: pointer;
    color: var(--text2);
    border-bottom: 2px solid transparent;
    font-size: 0.875rem;
    font-weight: 500;
    transition: color 0.15s, border-color 0.15s;
  }
  .tab:hover { color: var(--text); }
  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .panel { display: none; }
  .panel.active { display: block; }

  /* Network cards */
  .net-grid {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .net-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
  }
  .net-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
  }
  .net-name {
    font-size: 1.1rem;
    font-weight: 600;
  }
  .net-id {
    font-size: 0.7rem;
    color: var(--text2);
    font-family: monospace;
  }
  .badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge-success { background: rgba(52, 211, 153, 0.15); color: var(--green); }
  .badge-fail { background: rgba(248, 113, 113, 0.15); color: var(--red); }
  .badge-tier { background: rgba(108, 140, 255, 0.15); color: var(--accent); }

  .net-body {
    display: flex;
    flex-wrap: wrap;
    gap: 1.25rem;
  }
  .net-section {
    flex: 1;
    min-width: 160px;
  }
  .net-section-title {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text2);
    margin-bottom: 0.35rem;
  }
  .tag-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }
  .tag {
    background: var(--tag-bg);
    color: var(--text2);
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-family: monospace;
  }
  table.mini {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  table.mini th {
    text-align: left;
    color: var(--text2);
    font-weight: 500;
    padding: 0.25rem 0.5rem 0.25rem 0;
    border-bottom: 1px solid var(--border);
  }
  table.mini td {
    padding: 0.25rem 0.5rem 0.25rem 0;
    border-bottom: 1px solid var(--border);
    font-family: monospace;
    font-size: 0.75rem;
  }
  .ts {
    font-size: 0.7rem;
    color: var(--text2);
    margin-top: 0.75rem;
  }

  /* Template view */
  .tpl-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1rem;
  }
  .tpl-header {
    padding: 1rem 1.25rem;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
  }
  .tpl-header:hover { background: var(--surface2); border-radius: 8px; }
  .tpl-title {
    font-weight: 600;
    font-size: 1rem;
  }
  .tpl-desc {
    color: var(--text2);
    font-size: 0.8rem;
  }
  .tpl-chevron {
    color: var(--text2);
    transition: transform 0.2s;
    font-size: 1.2rem;
  }
  .tpl-section.open .tpl-chevron { transform: rotate(90deg); }
  .tpl-body {
    display: none;
    padding: 0 1.25rem 1.25rem;
  }
  .tpl-section.open .tpl-body { display: block; }
  .tpl-sub {
    margin-top: 1rem;
  }
  .tpl-sub-title {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--accent);
    margin-bottom: 0.5rem;
  }
  table.tpl-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
    margin-bottom: 0.5rem;
  }
  table.tpl-table th {
    text-align: left;
    color: var(--text2);
    font-weight: 500;
    padding: 0.35rem 0.75rem 0.35rem 0;
    border-bottom: 1px solid var(--border);
  }
  table.tpl-table td {
    padding: 0.35rem 0.75rem 0.35rem 0;
    border-bottom: 1px solid var(--border);
  }
  table.tpl-table td.mono {
    font-family: monospace;
    font-size: 0.75rem;
  }
  .fw-deny { color: var(--red); }
  .fw-allow { color: var(--green); }
  .vpn-badge {
    display: inline-block;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
  }
  .vpn-yes { background: rgba(52, 211, 153, 0.15); color: var(--green); }
  .vpn-no { background: rgba(139, 145, 165, 0.1); color: var(--text2); }

  .addr-scheme {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
    font-size: 0.8rem;
    line-height: 1.8;
  }
  .addr-scheme code {
    font-family: monospace;
    color: var(--accent);
  }

  .raw-block {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    font-family: monospace;
    font-size: 0.78rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text);
    overflow-x: auto;
    max-height: 600px;
    overflow-y: auto;
  }
  .empty-state {
    text-align: center;
    padding: 3rem;
    color: var(--text2);
  }
  .loading {
    text-align: center;
    padding: 3rem;
    color: var(--text2);
  }
  @media (max-width: 600px) {
    body { padding: 1rem; }
    .net-grid { gap: 0.75rem; }
  }
</style>
</head>
<body>
<h1>Automation MCP</h1>
<p class="subtitle">Network provisioning registry and templates</p>

<div class="tabs">
  <div class="tab active" data-panel="registry">Managed Networks</div>
  <div class="tab" data-panel="templates">Branch Templates</div>
  <div class="tab" data-panel="raw">Raw Files</div>
</div>

<div id="registry" class="panel active">
  <div class="loading" id="reg-loading">Loading registry...</div>
  <div class="net-grid" id="reg-grid"></div>
</div>

<div id="templates" class="panel">
  <div class="addr-scheme">
    <strong>Addressing Scheme</strong><br>
    Corp &rarr; <code>10.{site_high}.{site_low}.0/24</code> (unique per site, routed over VPN)<br>
    Guest &rarr; <code>192.168.100.0/24</code> (same everywhere, local only)<br>
    VoIP &rarr; <code>10.{site_high}.{site_low+1}.0/24</code> (unique per site, routed over VPN)<br>
    IoT &rarr; <code>10.{site_high}.{site_low+2}.0/24</code> (unique per site, routed over VPN)
  </div>
  <div class="loading" id="tpl-loading">Loading templates...</div>
  <div id="tpl-container"></div>
</div>

<div id="raw" class="panel">
  <div class="tpl-section">
    <div class="tpl-header" onclick="this.parentElement.classList.toggle(&quot;open&quot;)">
      <div><div class="tpl-title">network_registry.yaml</div>
      <div class="tpl-desc">Managed network inventory</div></div>
      <span class="tpl-chevron">&#9654;</span>
    </div>
    <div class="tpl-body">
      <pre class="raw-block" id="raw-registry"></pre>
    </div>
  </div>
  <div class="tpl-section">
    <div class="tpl-header" onclick="this.parentElement.classList.toggle(&quot;open&quot;)">
      <div><div class="tpl-title">branch.yaml</div>
      <div class="tpl-desc">Branch network provisioning template</div></div>
      <span class="tpl-chevron">&#9654;</span>
    </div>
    <div class="tpl-body">
      <pre class="raw-block" id="raw-template"></pre>
    </div>
  </div>
</div>

<script data-cfasync="false">
  /*__INLINE_DATA__*/

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.panel).classList.add('active');
  });
});

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString('en-CA') + ' ' + d.toLocaleTimeString('en-CA', {hour:'2-digit',minute:'2-digit'});
}

// Render registry
(function() {
  const data = window.__REGISTRY__ || [];
  document.getElementById('reg-loading').style.display = 'none';
  const grid = document.getElementById('reg-grid');
  if (!data.length) {
    grid.innerHTML = '<div class="empty-state">No managed networks yet</div>';
    return;
  }
  data.forEach(net => {
    const status = net.provisioned_status || 'unknown';
    const badgeClass = status === 'success' ? 'badge-success' : 'badge-fail';
    let vlansHtml = '';
    if (net.vlans && net.vlans.length) {
      vlansHtml = '<table class="mini"><tr><th>ID</th><th>Name</th><th>Subnet</th></tr>';
      net.vlans.forEach(v => {
        vlansHtml += '<tr><td>' + esc(String(v.id)) + '</td><td>' + esc(v.name) + '</td><td>' + esc(v.subnet) + '</td></tr>';
      });
      vlansHtml += '</table>';
    }
    let ssidsHtml = '';
    if (net.ssids && net.ssids.length) {
      ssidsHtml = net.ssids.map(s => '<span class="tag">' + esc(s.name) + '</span>').join('');
    }
    let tagsHtml = '';
    if (net.tags && net.tags.length) {
      tagsHtml = net.tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('');
    }

    const card = document.createElement('div');
    card.className = 'net-card';
    card.innerHTML =
      '<div class="net-header">' +
        '<div><div class="net-name">' + esc(net.name) + '</div>' +
        '<div class="net-id">' + esc(net.network_id || '') + '</div></div>' +
        '<div><span class="badge badge-tier">' + esc(net.tier || '') + '</span> ' +
        '<span class="badge ' + badgeClass + '">' + esc(status) + '</span></div>' +
      '</div>' +
      '<div class="net-body">' +
        '<div class="net-section"><div class="net-section-title">VLANs</div>' + vlansHtml + '</div>' +
        '<div class="net-section"><div class="net-section-title">SSIDs</div><div class="tag-list">' + ssidsHtml + '</div></div>' +
        (net.product_types ? '<div class="net-section"><div class="net-section-title">Product Types</div><div class="tag-list">' + net.product_types.map(p => '<span class="tag">' + esc(p) + '</span>').join('') + '</div></div>' : '') +
        (net.vpn_mode ? '<div class="net-section"><div class="net-section-title">VPN</div><span class="tag">' + esc(net.vpn_mode) + '</span></div>' : '') +
        (tagsHtml ? '<div class="net-section"><div class="net-section-title">Tags</div><div class="tag-list">' + tagsHtml + '</div></div>' : '') +
      '</div>' +
      '<div class="ts">Provisioned: ' + esc(formatDate(net.provisioned_at)) +
        (net.last_modified ? ' &nbsp;&middot;&nbsp; Modified: ' + esc(formatDate(net.last_modified)) : '') + '</div>';
    grid.appendChild(card);
  });
})();

// Render templates
(function() {
  const data = window.__TEMPLATES__ || {};
  document.getElementById('tpl-loading').style.display = 'none';
  const container = document.getElementById('tpl-container');
  Object.entries(data).forEach(([tplName, tpl]) => {
    Object.entries(tpl.tiers || {}).forEach(([tierName, tier]) => {
      const section = document.createElement('div');
      section.className = 'tpl-section';

      // VLANs table
      let vlansHtml = '<table class="tpl-table"><tr><th>ID</th><th>Name</th><th>Subnet</th><th>Gateway</th><th>DHCP</th></tr>';
      (tier.vlans || []).forEach(v => {
        vlansHtml += '<tr><td>' + esc(String(v.id)) + '</td><td>' + esc(v.name) +
          '</td><td class="mono">' + esc(v.subnet) + '</td><td class="mono">' + esc(v.appliance_ip || '') +
          '</td><td>' + esc(v.dhcp_handling || '') + '</td></tr>';
      });
      vlansHtml += '</table>';

      // SSIDs table
      let ssidsHtml = '<table class="tpl-table"><tr><th>#</th><th>Name</th><th>Auth</th><th>VLAN</th><th>IP Mode</th></tr>';
      (tier.ssids || []).forEach(s => {
        ssidsHtml += '<tr><td>' + s.number + '</td><td>' + esc(s.name) +
          '</td><td>' + esc(s.auth_mode || '') + '</td><td>' + (s.default_vlan_id || '') +
          '</td><td>' + esc(s.ip_assignment_mode || '') + '</td></tr>';
      });
      ssidsHtml += '</table>';

      // Firewall rules
      let fwHtml = '<table class="tpl-table"><tr><th>Policy</th><th>Comment</th><th>Src</th><th>Dst</th><th>Proto</th></tr>';
      (tier.firewall_rules || []).forEach(r => {
        const cls = r.policy === 'deny' ? 'fw-deny' : 'fw-allow';
        fwHtml += '<tr><td class="' + cls + '">' + esc(r.policy) +
          '</td><td>' + esc(r.comment || '') + '</td><td class="mono">' + esc(r.src_cidr || '') +
          '</td><td class="mono">' + esc(r.dest_cidr || '') + '</td><td>' + esc(r.protocol || '') + '</td></tr>';
      });
      fwHtml += '</table>';

      // VPN
      let vpnHtml = '';
      if (tier.vpn) {
        vpnHtml = '<div><strong>Mode:</strong> ' + esc(tier.vpn.mode || '') + '</div>';
        if (tier.vpn.hubs && tier.vpn.hubs.length) {
          vpnHtml += '<div style="margin-top:0.35rem"><strong>Hubs:</strong> ' +
            tier.vpn.hubs.map(h => esc(h.name || h.hub_id)).join(', ') + '</div>';
        }
        if (tier.vpn.subnets && tier.vpn.subnets.length) {
          vpnHtml += '<table class="tpl-table" style="margin-top:0.5rem"><tr><th>Subnet</th><th>VPN</th></tr>';
          tier.vpn.subnets.forEach(s => {
            const cls = s.use_vpn ? 'vpn-yes' : 'vpn-no';
            vpnHtml += '<tr><td class="mono">' + esc(s.local_subnet) +
              '</td><td><span class="vpn-badge ' + cls + '">' + (s.use_vpn ? 'routed' : 'local') + '</span></td></tr>';
          });
          vpnHtml += '</table>';
        }
      }

      section.innerHTML =
        '<div class="tpl-header" onclick="this.parentElement.classList.toggle(&quot;open&quot;)">' +
          '<div><div class="tpl-title">' + esc(tierName.charAt(0).toUpperCase() + tierName.slice(1)) + '</div>' +
          '<div class="tpl-desc">' + esc(tier.description || '') + '</div></div>' +
          '<span class="tpl-chevron">&#9654;</span>' +
        '</div>' +
        '<div class="tpl-body">' +
          '<div class="tpl-sub"><div class="tpl-sub-title">VLANs</div>' + vlansHtml + '</div>' +
          '<div class="tpl-sub"><div class="tpl-sub-title">SSIDs</div>' + ssidsHtml + '</div>' +
          '<div class="tpl-sub"><div class="tpl-sub-title">Firewall Rules</div>' + fwHtml + '</div>' +
          '<div class="tpl-sub"><div class="tpl-sub-title">VPN</div>' + vpnHtml + '</div>' +
        '</div>';
      container.appendChild(section);
    });
  });
})();

// Render raw files
document.getElementById('raw-registry').textContent = window.__RAW_REGISTRY__ || '';
document.getElementById('raw-template').textContent = window.__RAW_TEMPLATE__ || '';
</script>
</body>
</html>"""


async def handle_dashboard(request: web.Request) -> web.Response:
    """Serve the dashboard HTML page with data inlined."""
    # Build registry JSON
    registry_data = json.dumps(load_registry(), default=str)

    # Build sanitized template JSON (strip PSKs)
    sanitized = {}
    for tpl_name, tpl_data in templates.items():
        sanitized[tpl_name] = {
            "product_types": tpl_data.get("product_types", []),
            "tiers": {},
        }
        for tier_name, tier_cfg in tpl_data.get("tiers", {}).items():
            tier_copy = {
                "description": tier_cfg.get("description", ""),
                "vlans": tier_cfg.get("vlans", []),
                "ssids": [],
                "firewall_rules": tier_cfg.get("firewall_rules", []),
                "vpn": tier_cfg.get("vpn", {}),
            }
            for ssid in tier_cfg.get("ssids", []):
                s = dict(ssid)
                if "psk" in s:
                    s["psk"] = "********"
                tier_copy["ssids"].append(s)
            sanitized[tpl_name]["tiers"][tier_name] = tier_copy
    templates_data = json.dumps(sanitized, default=str)

    # Read raw YAML files for the Raw Files tab
    raw_registry = ""
    try:
        with open(NETWORK_REGISTRY_PATH, "r") as f:
            raw_registry = f.read()
    except Exception:
        raw_registry = "(file not found)"

    raw_template = ""
    try:
        tpl_path = os.path.join(TEMPLATE_DIR, "branch.yaml")
        with open(tpl_path, "r") as f:
            raw_template = f.read()
    except Exception:
        raw_template = "(file not found)"

    # Escape for safe embedding in JS string
    raw_registry_js = json.dumps(raw_registry)
    raw_template_js = json.dumps(raw_template)

    # Inject data into HTML, replacing the fetch calls
    html = DASHBOARD_HTML.replace(
        "/*__INLINE_DATA__*/",
        f"window.__REGISTRY__ = {registry_data};\n"
        f"  window.__TEMPLATES__ = {templates_data};\n"
        f"  window.__RAW_REGISTRY__ = {raw_registry_js};\n"
        f"  window.__RAW_TEMPLATE__ = {raw_template_js};"
    )
    return web.Response(text=html, content_type="text/html")


# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/mcp", handle_mcp_request)
    app.router.add_post("/", handle_mcp_request)
    app.router.add_get("/health", health_check)
    app.router.add_get("/tools", list_tools_endpoint)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_get("/api/registry", handle_api_registry)
    app.router.add_get("/api/templates", handle_api_templates)
    app.router.add_get(
        "/.well-known/oauth-protected-resource",
        handle_protected_resource_metadata,
    )
    app.router.add_get(
        "/.well-known/oauth-authorization-server",
        handle_oauth_metadata,
    )
    app.router.add_get("/authorize", handle_authorize)
    app.router.add_post("/oauth/token", handle_oauth_token)
    return app


if __name__ == "__main__":
    initialize_meraki()
    load_tokens()
    load_templates()
    app = create_app()
    logger.info("Starting Automation MCP Server v1.0.0 on port 3003")
    logger.info(f"Tools available: {[t['name'] for t in TOOLS]}")
    logger.info(f"Templates loaded: {list(templates.keys())}")
    web.run_app(app, host="0.0.0.0", port=3003)
