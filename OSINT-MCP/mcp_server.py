from fastmcp import FastMCP, Context
import httpx
import os
import arrow  # For "1 day ago" formatting
import socket # For resolving domains to IPs

# Initialize FastMCP
mcp = FastMCP("Security-Analyst")

# --- HELPER FUNCTIONS ---

def format_stats(stats: dict) -> str:
    """Format VT stats into a clean string (e.g., 'Malicious: 5, Suspicious: 1')."""
    return ", ".join([f"{k.capitalize()}: {v}" for k, v in stats.items() if v > 0])

def get_relative_time(timestamp: int) -> str:
    """Convert Unix timestamp to relative time (e.g., '5 years ago')."""
    if not timestamp:
        return "Unknown"
    return arrow.get(timestamp).humanize()

def resolve_target_to_ip(target: str) -> str:
    """
    Helper to resolve a domain to an IP address. 
    Returns the IP string if successful, or None if resolution fails.
    If target is already an IP, it returns it as is.
    """
    try:
        # Check if it's already a valid IP
        socket.inet_aton(target)
        return target
    except socket.error:
        # It's likely a domain, try to resolve it
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

# --- TOOLS ---

@mcp.tool()
async def analyze_shodan(target: str, ctx: Context = None) -> str:
    """
    Analyze an IP or Domain via Shodan.
    Scans for: Open Ports, Vulnerabilities (CVEs), Organization, and OS.
    Returns ALL detected vulnerabilities without truncation.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return "Error: SHODAN_API_KEY not set."

    # 1. Resolve Domain to IP
    ip_address = resolve_target_to_ip(target)
    if not ip_address:
        return f"Error: Could not resolve '{target}' to an IP address."

    # 2. Query Shodan 
    # minify=true reduces bandwidth but still includes the 'vulns' list we need.
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}&minify=true"

    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        
        if resp.status_code == 404:
            return f"### Shodan Analysis: {target} ({ip_address})\n- **Status:** No information found in Shodan database."
        if resp.status_code != 200:
            return f"Error querying Shodan: {resp.status_code}"

        data = resp.json()

        # 3. Parse Data
        org = data.get("org", "Unknown Org")
        os_type = data.get("os", "Unknown OS")
        country = data.get("country_name", "Unknown Country")
        hostnames = data.get("hostnames", [])
        
        # Open Ports
        ports = data.get("ports", [])
        ports.sort()
        
        # Vulnerabilities (Full List)
        vulns = data.get("vulns", [])
        
        # 4. Format Output
        # JOIN ALL vulns. No [:5] limit.
        vuln_section = ", ".join(vulns) if vulns else "None detected"

        return (
            f"### Shodan Analysis: {target} ({ip_address})\n"
            f"- **Organization:** {org}\n"
            f"- **OS/Location:** {os_type} / {country}\n"
            f"- **Hostnames:** {', '.join(hostnames) if hostnames else 'N/A'}\n"
            f"- **Open Ports:** `{', '.join(map(str, ports))}`\n"
            f"- **Vulnerabilities ({len(vulns)}):** {vuln_section}"
        )

@mcp.tool()
async def analyze_ip(ip: str, ctx: Context = None) -> str:
    """
    Analyze IP via VirusTotal. 
    Returns: Location, Owner, Reputation, and ALL Related Campaigns (Tags).
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "Error: VT_API_KEY not set."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return f"Error querying VirusTotal: {resp.status_code}"
        
        data = resp.json().get("data", {}).get("attributes", {})
        
        country = data.get("country", "Unknown")
        owner = data.get("as_owner", "Unknown ASN")
        stats = data.get("last_analysis_stats", {})
        reputation = format_stats(stats)
        
        # Tags (Full List)
        tags = data.get("tags", [])
        # JOIN ALL tags. No [:5] limit.
        campaign_info = ", ".join(tags) if tags else "No specific campaign tags found"

        return (
            f"### VirusTotal IP: {ip}\n"
            f"- **Location:** {country}\n"
            f"- **Owner:** {owner}\n"
            f"- **Reputation:** {reputation}\n"
            f"- **Tags:** {campaign_info}"
        )

@mcp.tool()
async def analyze_hash(file_hash: str, ctx: Context = None) -> str:
    """
    Analyze File Hash via VirusTotal.
    Returns: Original Filename, Reputation, Popular Threat Label.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "Error: VT_API_KEY not set."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return f"Hash {file_hash} not found in VirusTotal."
        if resp.status_code != 200:
            return f"Error: {resp.status_code}"

        data = resp.json().get("data", {}).get("attributes", {})

        filename = data.get("meaningful_name") or (data.get("names", ["Unknown"])[0])
        stats = data.get("last_analysis_stats", {})
        reputation = format_stats(stats)
        pop_threat = data.get("popular_threat_classification", {})
        label = pop_threat.get("suggested_threat_label", "None")
        
        return (
            f"### VirusTotal Hash: {file_hash}\n"
            f"- **Filename:** {filename}\n"
            f"- **Reputation:** {reputation}\n"
            f"- **Label:** {label}"
        )

@mcp.tool()
async def analyze_domain(domain: str, ctx: Context = None) -> str:
    """
    Analyze Domain via VirusTotal.
    Returns: Creation Date (Relative), Reputation, Campaigns.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "Error: VT_API_KEY not set."

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return f"Error: {resp.status_code}"

        data = resp.json().get("data", {}).get("attributes", {})

        creation_ts = data.get("creation_date")
        created_str = get_relative_time(creation_ts)
        stats = data.get("last_analysis_stats", {})
        reputation = format_stats(stats)
        categories = data.get("categories", {})
        cats_str = ", ".join([v for k, v in categories.items()]) if categories else "None"

        return (
            f"### VirusTotal Domain: {domain}\n"
            f"- **Created:** {created_str}\n"
            f"- **Reputation:** {reputation}\n"
            f"- **Categories:** {cats_str}"
        )

@mcp.tool()
async def check_domain_radar(domain: str, ctx: Context = None) -> str:
    """
    Check Cloudflare Radar for Domain Categories.
    Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.
    """
    cf_token = os.getenv("CLOUDFLARE_API_TOKEN")
    cf_account = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    
    if not cf_token or not cf_account:
        return "Error: CLOUDFLARE_API_TOKEN or CLOUDFLARE_ACCOUNT_ID not set."

    url = f"https://api.cloudflare.com/client/v4/accounts/{cf_account}/intel/domain?domain={domain}"
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            content_cats = [c.get("name") for c in data.get("content_categories", [])]
            risk_cats = [c.get("name") for c in data.get("risk_types", [])]
            
            cats = ", ".join(content_cats + risk_cats)
            return f"### Cloudflare Radar: {domain}\n- **Categories:** {cats or 'Uncategorized'}"
        
        return f"Error querying Cloudflare: {resp.status_code}"

if __name__ == "__main__":
    mcp.run(transport="sse")
