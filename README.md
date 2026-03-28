# Automation MCP Server for Meraki Branch Provisioning

A Model Context Protocol (MCP) server that provisions complete Cisco Meraki branch networks from YAML templates. Define your network standards as templates, connect an LLM, and deploy entire branch sites — VLANs, SSIDs, firewall rules, VPN tunnels — through natural language.

## How It Works

The server exposes five tools over MCP that any compatible client (n8n, Claude Desktop, Claude Code) can call:

| Tool | Description |
|------|-------------|
| `auto_list_templates` | List available templates with tier descriptions and configurations |
| `auto_create_branch_network` | Provision a complete branch network from a template (supports dry run) |
| `auto_list_networks` | List all networks tracked in the master registry |
| `auto_get_network_config` | Retrieve full configuration of a managed network |
| `auto_update_branch_network` | Modify or delete a managed network — add/remove VLANs, SSIDs, firewall rules, tags (supports dry run) |

An LLM reads the templates, understands your network design, and executes provisioning through the Meraki Dashboard API. The network registry tracks every managed network's configuration as a YAML file, serving as both a config backup and context for the LLM.

## Template System

Templates are YAML files in the `templates/` directory. The included `branch.yaml` defines three tiers:

- **Small** — Corp + Guest (2 VLANs, 2 SSIDs, guest isolation firewall, VPN spoke)
- **Medium** — Adds VoIP (3 VLANs, 3 SSIDs, VoIP-to-Corp allow rules)
- **Large** — Adds IoT (4 VLANs, 4 SSIDs, full inter-VLAN segmentation)

Templates use variables that are auto-computed from the network name:

| Variable | Example (site 114) | Computation |
|----------|-------------------|-------------|
| `{name}` | 114 - Langley | Full network name |
| `{location}` | Langley | Text after the dash |
| `{site_number}` | 114 | Number before the dash |
| `{site_high}` | 0 | `site_number // 256` |
| `{site_low}` | 114 | `site_number % 256` |
| `{site_low_voip}` | 115 | `site_low + 1` |
| `{site_low_iot}` | 116 | `site_low + 2` |

This addressing scheme supports up to 65,279 unique sites with predictable, non-overlapping subnets.

**This is an example template.** Replace the VLANs, SSIDs, firewall rules, addressing scheme, and VPN configuration with your own standards. Add new templates for different site types (retail, warehouse, data center). The server loads all YAML files from the templates directory at startup.

## Quick Start

```bash
git clone https://github.com/crwickha/mcp_automation_demo.git
cd mcp_automation_demo
cp .env.example .env
```

Edit `.env` with your values:

```
MERAKI_API_KEY=your-meraki-api-key
MERAKI_ORG_ID=your-org-id
CLOUDFLARE_TUNNEL_TOKEN=your-tunnel-token
```

Configure your Cloudflare Tunnel to route your hostname to `http://automation-mcp:3003`, then:

```bash
docker compose up -d
```

Verify:

```bash
curl https://your-tunnel-hostname/health
```

## Connecting a Client

**n8n:** Add an MCP Client tool node with endpoint `http://automation-mcp:3003/mcp` (same Docker network) or `https://your-tunnel-hostname/mcp` (external).

**Claude Desktop / Claude Code:** Add the tunnel URL as an MCP server endpoint in your configuration.

The client auto-discovers the five tools. The LLM decides which to call based on your instructions.

## Project Structure

```
├── server.py                  # MCP server (5 tools, Meraki API, registry management)
├── templates/
│   └── branch.yaml            # Branch network template (small/medium/large tiers)
├── network_registry.yaml      # Master registry of all managed networks
├── docker-compose.yml         # Automation MCP server + Cloudflare Tunnel
├── Dockerfile                 # Python 3.11 slim container
├── requirements.txt           # aiohttp, meraki, pyyaml
└── .env.example               # Environment variable template
```

## Customization

- **Templates** — Edit `templates/branch.yaml` or add new YAML files for different site types
- **Addressing** — Modify `compute_site_octets()` in `server.py` or integrate with an IPAM system
- **VPN hubs** — Replace the hub network ID in your template
- **Wireless auth** — Change from PSK to 802.1X, RADIUS, or open in the SSID config
- **Additional tools** — Add new MCP tools by defining the schema and handler in `server.py`

## Blog Post

For a detailed walkthrough of the design, template system, and integration patterns, see the accompanying blog post: [Automating Branch Network Provisioning with MCP and Cisco Meraki](https://blog.craigsandbacon.com/blog/mcp-automation-demo/)
