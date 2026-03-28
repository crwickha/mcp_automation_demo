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
    return json.dumps({"count": len(entries), "networks": entries}, indent=2)


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
                "defaultVlanId": ssid_cfg.get("default_vlan_id", 1),
            }
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
# App setup
# ──────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/mcp", handle_mcp_request)
    app.router.add_post("/", handle_mcp_request)
    app.router.add_get("/health", health_check)
    app.router.add_get("/tools", list_tools_endpoint)
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
