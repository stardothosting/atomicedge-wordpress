# Atomic Edge Security

Connect your WordPress site to Atomic Edge for enterprise-grade WAF protection, real-time analytics, and advanced security tools.

| Field | Value |
|---|---|
| Requires at least | WordPress 5.8 |
| Tested up to | WordPress 6.9 |
| Requires PHP | 7.4 |
| Stable tag | 1.0.6 |
| License | GPLv2 or later |
| License URI | https://www.gnu.org/licenses/gpl-2.0.html |

## Description

Atomic Edge Security connects your WordPress site to the Atomic Edge WAF/CDN service, providing enterprise-grade security protection without the complexity.

## Features

- **Web Application Firewall (WAF)** - Block SQL injection, XSS, and other attacks with OWASP Core Rules
- **Real-time Analytics** - Monitor traffic, blocked threats, and security events in real-time
- **IP Access Control** - Easily whitelist or blacklist IP addresses and CIDR ranges
- **Geographic Blocking** - Block or allow access based on visitor country
- **Malware Scanner** - Scan WordPress files for modifications and suspicious code patterns
- **Vulnerability Scanner** - Check WordPress core, plugins, and themes for known vulnerabilities (requires Atomic Edge connection)
- **WAF Log Viewer** - See exactly what threats are being blocked

## How It Works

1. Sign up for an Atomic Edge account at https://atomicedge.io
2. Add your site to Atomic Edge and get your API key
3. Install this plugin and enter your API key
4. Manage your security settings directly from WordPress

Vulnerability scanning is available when connected and uses Atomic Edge's vulnerability data feed.

## Requirements

- PHP 7.4 or higher
- WordPress 5.8 or higher
- An Atomic Edge account (free tier available)
- OpenSSL PHP extension

## Installation

1. Upload the `atomicedge` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the “Plugins” menu in WordPress
3. Go to Atomic Edge > Settings and enter your API key
4. Your site is now protected

## Frequently Asked Questions

### Do I need an Atomic Edge account?

Yes, this plugin requires an Atomic Edge account to function. You can sign up for free at https://atomicedge.io.

### Is there a free tier?

Yes. Atomic Edge offers a free tier with basic WAF protection. Advanced features are available on paid plans.

### How do I get my API key?

After creating your Atomic Edge account and adding your site, you can generate an API key from the site settings page in your Atomic Edge dashboard.

### Does this plugin slow down my site?

No. The Atomic Edge WAF runs on our edge servers, not on your WordPress installation. The plugin only communicates with our API for configuration and analytics.

### Does the plugin include vulnerability scanning?

Yes. When your site is connected to Atomic Edge, you can run a vulnerability scan of WordPress core, plugins, and themes from the Atomic Edge admin menu.

### What attacks does the WAF block?

Atomic Edge uses the OWASP Core Rule Set to block:

- SQL Injection
- Cross-Site Scripting (XSS)
- Remote File Inclusion
- Local File Inclusion
- And many more common attack vectors

## Screenshots

1. Dashboard showing security summary
2. Analytics page with traffic graphs
3. WAF logs showing blocked attacks
4. IP access control management
5. Malware scanner results
6. Vulnerability scanner results

## Changelog

### 1.0.6

- Updated malware scanner results to show full file paths
- Improved vulnerability scanner UX (scan summary jump links and consistent “More Info” links)
- Simplified Settings page to focus on connection and core configuration

### 1.0.0

- Initial release
- WAF integration
- Analytics dashboard
- IP whitelist/blacklist management
- Geographic access control
- Malware scanner

## Upgrade Notice

### 1.0.0

Initial release of Atomic Edge Security plugin.
