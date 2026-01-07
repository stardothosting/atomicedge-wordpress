# AtomicEdge WordPress Plugin - Development Status

> **Status**: Frontend Complete, Awaiting Backend API
> **Last Updated**: January 6, 2026
> **WordPress Dev Environment**: http://shift8.local

## Overview

This WordPress plugin connects sites to the AtomicEdge WAF/CDN service, providing:
- Real-time traffic analytics with charts
- WAF security log viewing
- IP whitelist/blacklist management
- Geographic access control
- **Full-site malware scanning** (root, wp-admin, wp-includes, wp-content)
- **Vulnerability scanner** using WPScan API (free tier supported)

## File Structure (Complete)

```
atomicedge/
├── atomicedge.php                    # Main plugin file, constants, hooks
├── uninstall.php                     # Cleanup on uninstall
├── readme.txt                        # WordPress.org readme
├── .cursorrules                      # Cursor IDE rules
├── .github/
│   └── copilot-instructions.md       # GitHub Copilot guidance
├── includes/
│   ├── class-atomicedge.php          # Main singleton class
│   ├── class-atomicedge-api.php      # API client (encrypted key storage)
│   ├── class-atomicedge-admin.php    # Admin pages & menus
│   ├── class-atomicedge-ajax.php     # AJAX handlers
│   ├── class-atomicedge-scanner.php  # Malware scanner (full-site)
│   ├── class-atomicedge-vulnerability-scanner.php  # WPScan API integration
│   └── class-atomicedge-cron.php     # Scheduled tasks
├── admin/
│   ├── css/
│   │   └── admin.css                 # All admin styles
│   ├── js/
│   │   └── admin.js                  # AJAX handlers, Chart.js integration
│   └── views/
│       ├── dashboard.php             # Main dashboard with widgets
│       ├── settings.php              # Connection settings + WPScan token
│       ├── analytics.php             # Traffic analytics with charts
│       ├── waf-logs.php              # WAF log viewer
│       ├── access-control.php        # IP & Geo management (tabbed)
│       └── scanner.php               # Malware + Vulnerability scanner UI
├── assets/
│   ├── js/
│   │   └── chart.min.js              # Chart.js 4.4.1
│   └── images/                       # (empty, for future use)
└── languages/
    └── readme.txt                    # Translation placeholder
```

## API Configuration

### Default API URL
```
https://atomicedge.io/api/v1/wp
```

### Endpoints Used
- `GET/POST /connect` - Test connection
- `GET /analytics?period=24h` - Traffic data
- `GET /waf-logs?page=1&per_page=50&search=` - WAF logs
- `GET /ip-rules` - Get IP lists
- `POST /ip-rules/whitelist` - Add to whitelist
- `POST /ip-rules/blacklist` - Add to blacklist  
- `DELETE /ip-rules` - Remove IP
- `GET /geo-rules` - Get geo config
- `PUT /geo-rules` - Update geo rules

### Authentication
- Header: `X-AtomicEdge-Key: <api_key>`
- Key stored encrypted in `wp_options` using `AUTH_KEY` + `SECURE_AUTH_KEY`

## Security Patterns Implemented

1. **Nonce Verification**: All AJAX calls verify `atomicedge_nonce`
2. **Capability Checks**: `manage_options` required for all admin pages
3. **Input Sanitization**: All inputs sanitized before use
4. **Output Escaping**: All output escaped with `esc_html()`, `esc_attr()`, etc.
5. **Encrypted Storage**: API key encrypted at rest
6. **Direct Access Prevention**: All PHP files check `ABSPATH`

## AJAX Actions Registered

| Action | Handler | Description |
|--------|---------|-------------|
| `atomicedge_get_analytics` | `ajax_get_analytics()` | Fetch analytics data |
| `atomicedge_get_waf_logs` | `ajax_get_waf_logs()` | Fetch WAF logs |
| `atomicedge_get_ip_rules` | `ajax_get_ip_rules()` | Get IP whitelist/blacklist |
| `atomicedge_add_ip_whitelist` | `ajax_add_ip_whitelist()` | Add IP to whitelist |
| `atomicedge_add_ip_blacklist` | `ajax_add_ip_blacklist()` | Add IP to blacklist |
| `atomicedge_remove_ip` | `ajax_remove_ip()` | Remove IP from list |
| `atomicedge_get_geo_rules` | `ajax_get_geo_rules()` | Get geo access rules |
| `atomicedge_update_geo_rules` | `ajax_update_geo_rules()` | Update geo rules |
| `atomicedge_run_scan` | `ajax_run_scan()` | Run malware scan |
| `atomicedge_run_vulnerability_scan` | `ajax_run_vulnerability_scan()` | Check plugins/themes against WPScan |
| `atomicedge_get_vulnerability_results` | `ajax_get_vulnerability_results()` | Get cached vulnerability results |
| `atomicedge_save_wpscan_token` | `ajax_save_wpscan_token()` | Save WPScan API token |
| `atomicedge_get_wpscan_status` | `ajax_get_wpscan_status()` | Check WPScan API status |
| `atomicedge_clear_cache` | `ajax_clear_cache()` | Clear API cache |

## Malware Scanner Features

1. **WordPress Core Integrity**: Compares core files against WordPress.org checksums
2. **Full-Site Scanning**: Scans WordPress root, wp-admin, wp-includes, and all wp-content directories
3. **Root File Detection**: Flags unknown PHP files in WordPress root (not part of core)
4. **Suspicious Patterns**: Detects base64_decode, eval, shell_exec, webshell signatures
5. **PHP in Uploads**: Finds PHP files in wp-content/uploads (should not exist)
6. **Memory-Aware**: Monitors memory usage and stops gracefully if approaching limits
7. **Time-Aware**: Extends execution time on hosts that allow it

## Vulnerability Scanner Features

1. **WPScan Integration**: Uses WPScan Vulnerability Database API
2. **Free Tier Support**: Works with free API token (25 calls/day)
3. **WordPress Core Check**: Checks current WP version for known vulnerabilities
4. **Plugin Scanning**: Scans all installed plugins for CVEs
5. **Theme Scanning**: Scans all installed themes for vulnerabilities
6. **Version Filtering**: Only shows vulnerabilities affecting installed versions
7. **12-Hour Caching**: Caches results to minimize API calls
8. **Severity Levels**: Categorizes as critical, high, medium, or low

## Cron Jobs

| Hook | Schedule | Action |
|------|----------|--------|
| `atomicedge_daily_scan` | Daily | Run malware scan |
| `atomicedge_sync_settings` | Twice Daily | Sync settings with API |

## Options Stored

| Option Key | Description |
|------------|-------------|
| `atomicedge_api_key` | Encrypted API key |
| `atomicedge_site_domain` | Connected domain |
| `atomicedge_api_url` | API base URL |
| `atomicedge_cache_ttl` | Cache duration (seconds) |
| `atomicedge_last_scan` | Last malware scan results |
| `atomicedge_wpscan_api_token` | WPScan API token |
| `atomicedge_vuln_scan_results` | Last vulnerability scan results |
| `atomicedge_vuln_scan_time` | Last vulnerability scan timestamp |

## Testing Checklist

- [ ] Plugin activates without errors
- [ ] Settings page loads
- [ ] API connection works with valid key
- [ ] Analytics charts render
- [ ] WAF logs load and paginate
- [ ] IP whitelist/blacklist CRUD works
- [ ] Geo rules update successfully
- [ ] Malware scanner runs
- [ ] Cron jobs scheduled
- [ ] Uninstall cleans up all data

## Known Snyk Findings (Acceptable)

The following Snyk findings are **false positives** in context:

1. **MD5 for cache keys** (class-atomicedge-api.php:212) - MD5 used for cache key generation, not password hashing
2. **MD5 for file checksums** (class-atomicedge-scanner.php) - Required to match WordPress.org's checksum format

## Related Documentation

- AtomicEdge API: `/home/ck/git/shift8-projects/atomicedge.local/WORDPRESS_PLUGIN_INTEGRATION.md`
- Multi-root Workspace: `/home/ck/git/shift8-projects/atomicedge-fullstack.code-workspace`
