import os
import requests
import csv
import argparse
import json

# -----------------------------
# ARGUMENT PARSING
# -----------------------------
parser = argparse.ArgumentParser(description="Export F5 XC HTTP Load Balancer WAF configuration to CSV")
parser.add_argument("--tenant", type=str, required=True, help="Tenant name (used in API URL)")
parser.add_argument("--namespace", type=str, default="system", help="Namespace name or 'system' for all namespaces")
parser.add_argument("--output", type=str, default="f5_http_lb_waf_export.csv", help="CSV output file name")
parser.add_argument("--debug", action="store_true", help="Print API requests/responses for debugging")
args = parser.parse_args()

TENANT = args.tenant
NAMESPACE = args.namespace
CSV_FILE = args.output
DEBUG = args.debug

# -----------------------------
# CONFIGURATION
# -----------------------------
API_BASE = f"https://{TENANT}.console.ves.volterra.io/api"
API_TOKEN = os.environ.get("F5_XC_API_TOKEN")
if not API_TOKEN:
    raise ValueError("Environment variable F5_XC_API_TOKEN not set!")

HEADERS = {
    "Authorization": f"APIToken {API_TOKEN}",
    "Content-Type": "application/json"
}

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def debug_print_request_response(method, url, resp=None):
    if DEBUG:
        print("\n" + "="*80)
        print(f"API Request: {method} {url}")
        if resp is not None:
            try:
                resp_json = resp.json()
                print("Response JSON:\n", json.dumps(resp_json, indent=2))
            except Exception:
                print("Response text:\n", resp.text)
        print("="*80 + "\n")

def get_namespaces():
    """Return list of namespaces:
       - If user specified namespace != system → return [namespace]
       - If namespace == system → fetch all namespaces from tenant
    """
    if NAMESPACE != "system":
        return [NAMESPACE]

    url = f"{API_BASE}/web/namespaces"
    resp = requests.get(url, headers=HEADERS)
    resp.raise_for_status()
    debug_print_request_response("GET", url, resp)
    return [ns['name'] for ns in resp.json().get('items', [])]

def get_http_loadbalancers(namespace):
    url = f"{API_BASE}/config/namespaces/{namespace}/http_loadbalancers"
    resp = requests.get(url, headers=HEADERS)
    resp.raise_for_status()
    debug_print_request_response("GET", url, resp)
    items = resp.json().get('items', [])
    return [lb.get('name') for lb in items if lb.get('name')]

def get_lb_details(namespace, lb_name):
    url = f"{API_BASE}/config/namespaces/{namespace}/http_loadbalancers/{lb_name}"
    resp = requests.get(url, headers=HEADERS)
    resp.raise_for_status()
    debug_print_request_response("GET", url, resp)
    return resp.json()

def get_app_firewall_details(namespace, waf_name):
    """Fetch detailed App Firewall info for a given name. Returns tuple: (details_dict, source_namespace)"""
    if not waf_name:
        return {}, None

    # Try requested namespace
    url = f"{API_BASE}/config/namespaces/{namespace}/app_firewalls/{waf_name}"
    try:
        resp = requests.get(url, headers=HEADERS)
        resp.raise_for_status()
        debug_print_request_response("GET", url, resp)
        return resp.json(), namespace
    except requests.exceptions.HTTPError:
        if resp.status_code != 404:
            raise
        if DEBUG:
            print(f"WARNING: App Firewall '{waf_name}' not found in namespace '{namespace}', trying 'shared'.")

    # Try shared namespace
    if namespace != "shared":
        url = f"{API_BASE}/config/namespaces/shared/app_firewalls/{waf_name}"
        try:
            resp = requests.get(url, headers=HEADERS)
            resp.raise_for_status()
            debug_print_request_response("GET", url, resp)
            return resp.json(), "shared"
        except requests.exceptions.HTTPError:
            if resp.status_code != 404:
                raise
            if DEBUG:
                print(f"WARNING: App Firewall '{waf_name}' not found in 'shared', treating as waf_disabled.")
    return {}, None

def get_waf_mode(app_firewall_details):
    if not app_firewall_details:
        return ""
    spec = app_firewall_details.get('spec', {})
    if 'monitoring' in spec:
        return 'monitoring'
    elif 'blocking' in spec:
        return 'blocking'
    return ""

def extract_waf_rows(lb_details):
    """Return list of rows: first for default WAF, then per route"""
    rows = []
    if not lb_details:
        return rows

    namespace = lb_details.get('metadata', {}).get('namespace', '')
    lb_name = lb_details.get('metadata', {}).get('name', '')
    spec = lb_details.get('spec', {})

    # --- Default WAF ---
    if 'disable_waf' in spec or 'app_firewall' not in spec:
        default_waf_name = "waf_disabled"
        default_waf_mode = "NA"
    else:
        default_waf_name = spec.get('app_firewall', {}).get('name')
        default_waf_info, default_source_ns = get_app_firewall_details(namespace, default_waf_name) if default_waf_name else ({}, None)
        default_waf_mode = get_waf_mode(default_waf_info)
        if default_source_ns == "shared" and default_waf_name:
            default_waf_name += " (shared)"

    rows.append({
        "namespace": namespace,
        "lb_name": lb_name,
        "route": "NA",
        "waf_name": default_waf_name or "waf_disabled",
        "waf_mode": default_waf_mode or "NA"
    })

    # --- Routes ---
    for route in spec.get('routes', []):
        simple_route = route.get('simple_route') or {}
        advanced_options = simple_route.get('advanced_options') or {}

        # Capture path information (prefix, regex, exact, etc.)
        path_info = simple_route.get('path', {})
        if path_info:
            path_parts = [f"{k}={v}" for k, v in path_info.items()]
            route_path = "; ".join(path_parts)
        else:
            route_path = "NA"

        if 'disable_waf' in advanced_options:
            waf_name = "waf_disabled"
            waf_mode = "NA"
        elif 'app_firewall' in advanced_options and advanced_options['app_firewall'].get('name'):
            waf_name = advanced_options['app_firewall']['name']
            waf_info, source_ns = get_app_firewall_details(namespace, waf_name)
            if not waf_info:
                waf_name = "waf_disabled"
                waf_mode = "NA"
            else:
                waf_mode = get_waf_mode(waf_info)
                if source_ns == "shared":
                    waf_name += " (shared)"
        else:
            waf_name = default_waf_name or "waf_disabled"
            waf_mode = default_waf_mode or "NA"

        rows.append({
            "namespace": namespace,
            "lb_name": lb_name,
            "route": route_path,
            "waf_name": waf_name,
            "waf_mode": waf_mode
        })

    return rows

# -----------------------------
# MAIN SCRIPT
# -----------------------------
all_rows = []

for ns in get_namespaces():
    lb_names = get_http_loadbalancers(ns)
    for lb_name in lb_names:
        lb_details = get_lb_details(ns, lb_name)
        lb_rows = extract_waf_rows(lb_details)
        all_rows.extend(lb_rows)

# Write CSV
fieldnames = ["namespace", "lb_name", "route", "waf_name", "waf_mode"]
if all_rows:
    with open(CSV_FILE, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)
    print(f"CSV file '{CSV_FILE}' generated successfully!")
else:
    print("No HTTP load balancer data found.")
