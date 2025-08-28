# F5 XC HTTP LB WAF Export – README

Export **F5 Distributed Cloud (XC)** HTTP Load Balancer WAF configuration (default + per-route) to a CSV.

---

## What this tool does

* Authenticates to F5 XC using `F5_XC_API_TOKEN`.
* Scans **one namespace** or **all namespaces** (`--namespace system`).
* For each HTTP LB, collects:

  * **Default WAF** (or marks `waf_disabled` if disabled/missing).
  * **Per-route WAF** overrides and **route path** (prefix/regex/exact).
  * **WAF mode**: `blocking`, `monitoring`, or `NA`.
* Falls back to **shared** namespace for WAFs and annotates as `name (shared)`.
* Writes a tidy CSV:
  `namespace, lb_name, route, waf_name, waf_mode`.

---

## Prerequisites

* Python 3.8+
* Packages: `requests` (stdlib `csv`/`argparse`/`json` are used)
* An XC API token with read access to:

  * Namespaces
  * HTTP Load Balancers
  * App Firewalls

> **Security:** store your token in an env var; do **not** hardcode it.

---

## Install

```bash
# (recommended) create and activate a venv
python3 -m venv venv
source venv/bin/activate

# install dependency
pip install requests
```

---

## Configure auth

```bash
export F5_XC_API_TOKEN="<your_api_token>"
```

---

## Usage

```bash
python3 f5_lb_waf_export.py \
  --tenant sdc-support \
  --namespace coderyogi \
  --output my_lb_waf.csv \
  --debug
```

### Scan all namespaces in the tenant

```bash
python3 f5_lb_waf_export.py \
  --tenant sdc-support \
  --namespace system \
  --output all_lb_waf.csv
```

* If `--namespace` is **not** `system`: only that namespace is scanned.
* If `--namespace` is **`system`**: the tool lists **all** namespaces and scans each.

---

## Output format (CSV)

Columns (in order):

1. `namespace` – LB namespace
2. `lb_name` – HTTP Load Balancer name
3. `route` – route path; may be:

   * `prefix=/foo`
   * `regex=^/v[0-9]+/users$`
   * `exact=/healthz`
   * `NA` (for the default row representing LB-level config)
4. `waf_name` – WAF policy name, `name (shared)` if from shared, or `waf_disabled`
5. `waf_mode` – `blocking`, `monitoring`, or `NA`

### Example

```csv
namespace,lb_name,route,waf_name,waf_mode
coderyogi,f5demo-15043,NA,waf_disabled,NA
coderyogi,f5demo-15043,prefix=/,lb-default,NA
coderyogi,f5demo-coderyogi,NA,f5demo-waf,blocking
coderyogi,f5demo-coderyogi,prefix=/,f5demo-waf-monitoring,monitoring
coderyogi,f5demo-coderyogi,regex=^/no-waf$,waf_disabled,NA
coderyogi,f5demo-coderyogi,prefix=/fwd-waf,fwd-waf-shared (shared),blocking
```

---

## How WAF is determined

* **LB default row (`route=NA`)**

  * If `spec.disable_waf` **present** **or** `spec.app_firewall` **missing**
    → `waf_name=waf_disabled`, `waf_mode=NA`
  * Else, use `spec.app_firewall.name` and fetch its details to determine mode
    → `monitoring` if `spec.monitoring` present
    → `blocking` if `spec.blocking` present
    → annotate `(shared)` when fetched from the `shared` namespace

* **Per-route rows**

  * If `simple_route.advanced_options.disable_waf` present
    → `waf_name=waf_disabled`, `waf_mode=NA`
  * Else if `simple_route.advanced_options.app_firewall.name` present
    → fetch that WAF to determine mode (with shared fallback)
  * Else
    → inherit LB default (`lb-default` + default mode)

* **Route path** is rendered from whichever of `prefix`, `regex`, `exact` appears in `simple_route.path`. Multiple keys are joined with `; `.

---

## APIs used

Base: `https://{TENANT}.console.ves.volterra.io/api`

* **List namespaces** (when `--namespace system`):
  `GET /web/namespaces`
* **List HTTP LBs in a namespace**:
  `GET /config/namespaces/{namespace}/http_loadbalancers`
* **Get HTTP LB details**:
  `GET /config/namespaces/{namespace}/http_loadbalancers/{name}`
* **Get App Firewall details**:
  `GET /config/namespaces/{namespace}/app_firewalls/{waf_name}`
  Fallback:
  `GET /config/namespaces/shared/app_firewalls/{waf_name}`

---

## Debugging

Add `--debug` to print each API request and pretty-printed JSON responses:

```bash
python3 f5_lb_waf_export.py --tenant sdc-support --namespace coderyogi --output out.csv --debug
```

---

## Troubleshooting

* **401/403**: Check `F5_XC_API_TOKEN` and permissions.
* **404 on `/web/namespaces`**: Verify tenant and base URL; ensure `--namespace system` was intended.
* **Empty CSV**: Confirm LBs exist and your token can read them.
* **Shared WAFs not found**: Ensure the policy actually exists in `shared`.

---

## Notes / Limitations

* Only HTTP Load Balancers are covered.
* WAF mode detection relies on presence of `spec.monitoring` or `spec.blocking` in App Firewall objects.
* Script is **read-only**; no configuration changes are made.

---

## Contributing

* Open a PR with clear description and sample payloads if adding new match types or resources.
* Keep output schema backward-compatible when possible.

---

## License

Internal use / customer-guided use. Adapt as needed for your environment.
