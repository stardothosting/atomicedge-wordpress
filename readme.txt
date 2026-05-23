=== Atomic Edge Security - Firewall, Malware Scan and Login Security ===
Contributors: shift8
Tags: 2FA, Firewall, Malware, Scanner, Security
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress firewall with cloud WAF rules, malware scanning, 2FA, vulnerability checks, IP blocking, and real-time security logs.

== Description ==

Atomic Edge Security is a WordPress firewall plugin that protects your site with cloud-based WAF rules, malware scanning, 2FA, vulnerability checks, IP blocking, and real-time security logs.

It blocks malicious traffic before it reaches WordPress while giving site owners firewall controls directly inside the WordPress admin.

[youtube https://youtu.be/1_y-mRHpMK0]

= WordPress Firewall Protection =

Atomic Edge includes a cloud-based WordPress firewall that helps block malicious traffic before it reaches your website. The firewall protects against common attacks such as SQL injection, cross-site scripting (XSS), local file inclusion, remote file inclusion, brute-force login attempts, and suspicious bot activity.

= Web Application Firewall (WAF) =

The Atomic Edge WAF uses OWASP Core Rules and WordPress-specific security rules to protect high-risk areas such as wp-login.php, wp-admin, XML-RPC, REST API endpoints, vulnerable plugin paths, and common exploit patterns.

= Features =

* **Two-Factor Authentication (2FA)** - Protect WordPress logins with TOTP authenticator apps (Google Authenticator, Authy, etc.)
* **2FA Enforcement Policies** - Require 2FA for specific user roles with configurable grace periods
* **2FA Audit Logging** - Complete security audit trail for all 2FA events
* **Adaptive Defense** - AI-powered threat detection that automatically identifies and blocks malicious actors
* **Web Application Firewall (WAF)** - Block SQL injection, XSS, and other attacks with OWASP Core Rules
* **Content Delivery Network (CDN)** - Serve static assets from global edge servers for faster page loads
* **Real-time Analytics** - Monitor traffic, blocked threats, and security events in real-time
* **IP Access Control** - Easily whitelist or blacklist IP addresses and CIDR ranges
* **Geographic Blocking** - Block or allow access based on visitor country
* **Malware Scanner** - Scan WordPress files for modifications and suspicious code patterns
* **Vulnerability Scanner** - Check WordPress core, plugins, and themes for known vulnerabilities (requires Atomic Edge connection)
* **WAF Log Viewer** - See exactly what threats are being blocked
* **WP-CLI Integration** - Run security scans from the command line

= How It Works =

1. Sign up for an Atomic Edge account at [atomicedge.io](https://atomicedge.io)
2. Add your site to Atomic Edge and get your API key
3. Install this plugin and enter your API key
4. Manage your security settings directly from WordPress

Vulnerability scanning is available when connected and uses Atomic Edge's vulnerability data feed.

= Requirements =

* PHP 7.4 or higher
* WordPress 5.8 or higher
* An Atomic Edge account (free tier available)
* OpenSSL PHP extension

== Installation ==

1. Upload the `atomic-edge-security` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to Atomic Edge > Settings and enter your API key
4. Your site is now protected!

== Frequently Asked Questions ==

= Do I need an Atomic Edge account? =

Yes, this plugin requires an Atomic Edge account to function. You can sign up for free at [atomicedge.io](https://atomicedge.io).

= Is there a free tier? =

Yes! Atomic Edge offers a free tier with basic WAF protection. Advanced features are available on paid plans.

= How do I get my API key? =

After creating your Atomic Edge account and adding your site, you can generate an API key from the site settings page in your Atomic Edge dashboard.

= Does this plugin slow down my site? =

No. The Atomic Edge WAF runs on our edge servers, not on your WordPress installation. The plugin only communicates with our API for configuration and analytics.

= Does the plugin include vulnerability scanning? =

Yes. When your site is connected to Atomic Edge, you can run a vulnerability scan of WordPress core, plugins, and themes from the Atomic Edge admin menu.

= What attacks does the WAF block? =

Atomic Edge uses the OWASP Core Rule Set to block:
* SQL Injection
* Cross-Site Scripting (XSS)
* Remote File Inclusion
* Local File Inclusion
* And many more common attack vectors

= Does Two-Factor Authentication (2FA) work without an Atomic Edge account? =

Yes! The 2FA feature works independently and does not require an Atomic Edge account or API connection. It uses industry-standard TOTP (Time-based One-Time Password) compatible with Google Authenticator, Authy, 1Password, and other authenticator apps.

= What are the server requirements for 2FA? =

2FA requires PHP 7.2+ with either:
* Native libsodium extension (recommended, included in most modern PHP installations), OR
* WordPress 5.2+ (which includes sodium_compat, a pure PHP fallback)

The plugin automatically detects and uses the best available option.

== Screenshots ==

1. Dashboard summary showing connection status, security overview, and quick actions
2. Analytics page with traffic graphs and data for requests and blocked threats
3. WAF log viewer displaying security incidents and blocked attacks in real-time
4. Access control management for IP whitelist, blacklist, and geographic blocking
5. Malware scanner to scan your entire WordPress installation for malicious files
6. Vulnerability scanner highlighting insecure or vulnerable core, themes, and plugins
7. CDN settings page for configuring content delivery and asset optimization
8. Two-Factor Authentication settings for securing WordPress login with TOTP apps
9. Adaptive Defense dashboard showing AI-powered threat detections and automatic IP blocking

== Changelog ==

= 2.8.0 =
* CHANGE: Confirmed compatibility with WordPress 7.0 after full plugin test validation and compatibility review

= 2.7.0 =
* CHANGE: Minor release for malware scanner timeout resilience and progress reporting improvements

= 2.6.0 =
* FIX: Malware scanner now uses shorter resumable AJAX steps to avoid gateway timeouts on varied hosting stacks
* FIX: Scanner retries with smaller steps after gateway-style timeout failures instead of failing immediately
* FIX: Abandoned scan queue items are recovered when a request is killed mid-scan
* FIX: Scans no longer finalize while queue items are still processing
* FIX: Thorough scan progress now counts all directories the scanner actually processes and smooths ETA updates

= 2.5.6 =
* CHANGE: Updated WordPress.org directory title, tags, and short description for better discoverability

= 2.5.4 =
* FIX: Minification persisted after being disabled — stale cached files were not cleared on toggle off
* FIX: Clear minification cache button silently failed — wp_delete_file() return value was incorrectly checked
* FIX: Cache clear now verifies file deletion with file_exists() and reports accurate deleted count
* CHANGE: Disabling CSS or JS minification now auto-clears the minification cache
* CLEANUP: Removed dead AJAX handler with mismatched nonce in CDN class

= 2.5.3 =
* FIX: Removed hardcoded malware signature strings from scanner that triggered ClamAV false-positive (Txt.Backdoor.Webshell-9891631-0) on hosting providers
* CHANGE: Refined plugin patterns now sourced exclusively from API instead of local hardcoded strings

= 2.5.2 =
* FIX: CDN toggle not persisting after save — hourly cron sync was overwriting CDN data instead of merging
* FIX: Saving CDN settings from Minification or Advanced tabs incorrectly disabled CDN
* FIX: Removed debug logging from CDN settings save handler

= 2.5.1 =
* CHANGE: WAF Logs "Block IP" button renamed to "Blacklist" — now adds IPs to edge-level IP Blacklist instead of Adaptive Defense
* NEW: Dev mode support for WAF logs blacklist button
* NEW: AJAX nonce auto-refresh — expired nonces are transparently refreshed without page reload

= 2.5.0 =
* NEW: Vulnerability scanner now works without an API key — free scans limited to 3 per day per IP
* NEW: Rate limit exceeded warning displayed in dashboard when daily scan limit is reached
* CHANGE: Vulnerability scanner availability no longer gated on API connection status

= 2.4.8 =
* NEW: Added Blocked IPs tab to Adaptive Defense with IP Address, Threat Score, WAF Hits, Type, Blocked, Expires columns and actions (Extend, Make Permanent, Unblock)
* FIX: Adaptive Defense block actions now route through dashboard Blocked IPs (application-layer) instead of Access Control IP blacklist (edge config)
* NEW: Manual block form on Blocked IPs tab with configurable duration (1h, 6h, 24h, 7d, 30d, permanent)
* NEW: Extend block (+1 day) and Make Permanent actions for timed blocks
* CHANGE: WAF Logs "Block IP" button renamed to "Blacklist IP" to clarify it adds to edge-level IP blacklist
* NEW: Added extend_block() and make_permanent() API methods and AJAX handlers with dev mode support

= 2.4.7 =
* FIX: Confidence now displayed as percentage (e.g. "90%") instead of raw decimal ("0.90%") in Adaptive Defense threat detection details
* FIX: Dev mode simulation data now uses 0.0-1.0 decimal values for confidence to match real API format

= 2.4.6 =
* FIX: Adaptive Defense dev mode now provides simulated data for all 8 AJAX endpoints (overview, actor profiles, threat detections, detection detail, block/unblock IP, dismiss detection, delete actor)
* FIX: Fixed duplicate detail rows appending on repeated "View Details" clicks in Threat Detections tab by replacing invalid <div>-wrapped <tr> template with HTML5 <template> element
* FIX: Added JS field name fallback chains for API response compatibility across versions
* NEW: Added 36 new tests for Adaptive Defense dev mode simulation and AJAX interception

= 2.4.5 =
* NEW: Added internationalization (i18n) support with load_plugin_textdomain() and .pot translation template
* Plugin is now translatable via WordPress.org GlotPress (translate.wordpress.org)
* Supports English (Canada) and all other WordPress locales

= 2.4.4 =
* FIX: Fixed fatal error "Class AtomicEdge_Cron not found" on plugin activation by ensuring Cron class is loaded before use in activation hook

= 2.4.3 =
* FIX: Corrected push.exclude to properly exclude top-level assets folder while preserving admin/assets
* FIX: Removed nested trunk folder from 2.0.0 tag in WordPress.org SVN
* FIX: Removed .dccache from SVN trunk
* FIX: Cleaned up malware signature patterns from test files to prevent false positives

= 2.4.2 =
* FIX: Removed hardcoded malware signatures from test files to prevent false positives from external security scanners
* Tests now use API-provided patterns via mocked API instead of inline signature strings

= 2.4.1 =
* FIX: Removed assets folder from plugin trunk/tags in WordPress.org SVN (assets should only exist in svn/assets for directory page)
* FIX: Cleaned up all existing SVN tags that incorrectly contained assets folder

= 2.4.0 =
* COMPLIANCE: Added External Services section to readme documenting API usage, data transmission, and links to Terms of Service and Privacy Policy
* COMPLIANCE: Text domain updated from 'atomicedge' to 'atomic-edge-security' to match WordPress.org plugin slug
* COMPLIANCE: All register_setting() calls now include sanitize_callback for proper input sanitization
* COMPLIANCE: Excluded WordPress.org directory assets from plugin zip file (assets/ folder now only syncs to SVN assets directory)

= 2.3.0 =
* NEW: Malware scanner signatures now fetched from public API (no API key required)
* This allows users to scan their site before registering with Atomic Edge
* FIX: API key migration for users who had raw keys stored (automatic re-encryption on load)
* IMPROVED: Test coverage for scanner with mocked API signatures

= 2.2.2 =
* FIX: Malware scanner signatures moved to remote API to prevent hosting providers from flagging the plugin as malware
* Signatures are now fetched from the Atomic Edge API and cached locally for 24 hours
* This resolves false positives from security scanners detecting plaintext malware patterns in the plugin source code

= 2.2.1 =
* FIX: Minification was running even when disabled (setting value 'off' is not empty)
* FIX: Clear minification cache button now returns proper response structure
* FIX: Test CDN button now uses correct dynamic path for any installation
* NEW: Weekly scheduled cleanup for minification cache (removes files older than 7 days)
* IMPROVED: Added 5 new tests for minification and cache cleanup

= 2.2.0 =
* NEW: Adaptive Defense - AI-powered threat detection and automatic IP blocking
* View real-time threat status and blocked IPs from the WordPress admin
* Actor profiles with behavioral analysis metrics
* Threat detection log with AI confidence scores
* Requires Atomic Edge Pro or Enterprise plan
* IMPROVED: API contract validation for better error messages

= 2.1.0 =
* MAJOR PERFORMANCE: Malware scanner now 100x faster through batch database operations
* NEW: Quick rejection pre-filter skips 93%+ of files before expensive regex matching
* NEW: Combined regex patterns per category reduce PCRE overhead
* NEW: Batch queue claiming (100 items per query vs 1) dramatically reduces DB load
* NEW: Batch completion marking (single UPDATE for batch vs per-file)
* NEW: Debug test button (WP_DEBUG only) for measuring scanner performance
* IMPROVED: Time budget increased to 45s max for capable servers
* IMPROVED: Native file_get_contents() for reads (WP-compliant, reduces overhead)

= 2.0.0 =
* MAJOR: CDN architecture overhaul - simplified URL management for better reliability
* REMOVED: User-configurable CDN URLs (prevented URL corruption bugs from form serialization)
* NEW: Developer constant support - define ATOMICEDGE_CDN_DEV_URL in wp-config.php for local testing
* IMPROVED: CDN enable logic simplified - now only checks local switch + CDN URL availability
* REMOVED: Dashboard status gating - CDN works with local settings only (no API calls required)
* FIXED: Consistent UI design pattern across all admin pages (logo, wrapper classes, headings)
* FIXED: 2FA settings page now matches design pattern of other plugin pages

= 1.9.9 =
* IMPROVED: Malware scanner now adapts to server performance (faster on capable servers)
* Scanner time budget auto-detects based on max_execution_time setting
* Adaptive polling reduces overhead on slow/shared hosting
* On servers with 30s timeout: ~15s per step; with 300s+: ~20s per step

= 1.9.8 =
* FIX: 2FA buttons (enable/disable) now work - JS was checking for wrong element ID after anchor fix

= 1.9.7 =
* FIX: 2FA encryption now works with sodium_compat polyfill (servers without native libsodium extension)
* sodium_memzero() calls now only execute when native libsodium is available

= 1.9.6 =
* FIX: 2FA setup link from admin notice now correctly scrolls to the 2FA section on profile page
* Fixed anchor ID mismatch (was #atomicedge-2fa, now #atomicedge-2fa-section)
* Added smooth scroll animation when navigating via hash link

= 1.9.5 =
* IMPROVED: Added comprehensive debug logging for 2FA enrollment when WP_DEBUG is enabled
* Debug logs show exact failure point in enrollment flow for easier troubleshooting
* Logs cover: crypto availability checks, encryption steps, user meta operations

= 1.9.4 =
* FIX: Removed problematic sodium_memzero() call on plaintext that could cause encryption failures
* IMPROVED: Encryption errors now show the exact underlying error message for easier diagnosis

= 1.9.3 =
* IMPROVED: 2FA enrollment now shows specific error messages (encryption unavailable, encryption failed, database issues)
* Better diagnostics for troubleshooting 2FA setup failures

= 1.9.2 =
* FIX: 2FA enrollment now works on servers with persistent object caching (Redis, Memcached)
* Added cache bypass for enrollment state verification
* Added debug logging for 2FA enrollment failures

= 1.9.1 =
* SECURITY: Fixed potential XSS vulnerability in JavaScript error message display (admin.js)
* Security audit: Verified proper escaping for all external data (WAF logs, analytics, 2FA audit logs)

= 1.9.0 =
* NEW: 2FA Audit Log - Security audit trail for all 2FA-related events
* Event logging: enrollment, disable, login success/failure, backup code usage, rate limiting
* Filterable log viewer with pagination (by user, event type, date)
* 30-day statistics dashboard with success/failure metrics
* Security events section highlighting failed logins and suspicious activity
* CSV export functionality for compliance and reporting
* 90-day log retention with automatic cleanup
* NEW: 2FA User Management - Admin interface for managing user 2FA status
* View all users with 2FA status (enabled/disabled)
* Search and filter users by 2FA status
* Admin reset capability for locked-out users
* Shows backup code counts and policy compliance status
* Confirmation dialog for reset actions with admin audit logging

= 1.8.0 =
* NEW: 2FA Enforcement Policy - Require two-factor authentication for specific user roles
* Role-based 2FA enforcement (Administrator, Editor, etc.)
* Configurable grace period before enforcement (1-90 days)
* Grace period bypass option - allow login during grace period with reminders
* Admin dashboard showing compliance status and non-compliant users
* Admin notice reminders for users who need to set up 2FA
* Dismissible reminders (24-hour reset) for less intrusive notifications
* Policy settings page with intuitive UI under Atomic Edge menu

= 1.7.0 =
* NEW: Two-Factor Authentication (2FA) for WordPress login protection
* TOTP authenticator app support (Google Authenticator, Authy, etc.)
* Backup recovery codes with secure generation and one-time use
* Encrypted secret storage using libsodium
* Rate limiting on failed 2FA attempts with progressive lockout
* 2FA settings integrated into User Profile page
* Client-side QR code generation for authenticator app setup

= 1.6.0 =
* Admin notice when retired Shift8 CDN plugin is active

= 1.5.0 =
* Malware Scanner: Cancel/Reset buttons now match Vulnerability Scanner sizing and spacing

= 1.4.0 =
* Malware Scanner: Cancel/Reset buttons now match Vulnerability Scanner styling
* Malware Scanner: Suspicious Files table formatting fixed
* Malware Scanner: Quick scan now skips excluded paths earlier (e.g., .git), reducing noise and improving speed
* Malware Scanner: Progress now uses stable totals and ETA
* Scanner: Core checksum verification now uses WordPress core verifier

= 1.3.7 =
* Fixed CDN settings sync: Brotli and image optimization now properly sync between plugin and AtomicEdge dashboard
* JS/CSS minification settings are now plugin-local only (they don't require edge-side configuration)
* CDN "Refresh Status" now pulls latest edge-side optimization settings from API

= 1.3.0 =
* Text domain updated to match WordPress.org plugin slug

= 1.3.3 =
* WordPress.org Plugin Review Team compliance: refactored path handling to use WordPress API functions instead of internal constants (ABSPATH, WP_PLUGIN_DIR, WP_CONTENT_DIR, WPMU_PLUGIN_DIR)
* WordPress.org Plugin Review Team compliance: AJAX handlers now sanitize all inputs at point of retrieval
* WordPress.org Plugin Review Team compliance: improved file inclusion guards for test compatibility
* Added recursive array sanitization support for complex AJAX request data

= 1.2.0 =
* Malware scanner: resumable scanning with DB-backed queue, improved progress reporting, and live activity log
* Malware scanner: quick (PHP-only) vs thorough (all files) scan modes (quick is default)
* Malware scanner: added Cancel Scan and Reset Scan controls (reset clears both state and saved results)
* Malware scanner: added optional AtomicEdge plugin integrity verification via shipped SHA-256 manifest
* Scanner diagnostics: clearer warnings for unreadable/partial scans and improved false-positive tuning

= 1.0.6 =
* Updated malware scanner results to show full file paths
* Improved vulnerability scanner UX (scan summary jump links and consistent "More Info" links)
* Simplified Settings page to focus on connection and core configuration

= 1.0.0 =
* Initial release
* WAF integration
* Analytics dashboard
* IP whitelist/blacklist management
* Geographic access control
* Malware scanner

== Upgrade Notice ==

= 2.8.0 =
Confirms WordPress 7.0 compatibility after full plugin test validation and compatibility review.

= 2.7.0 =
Improves malware scanner reliability and progress reporting after full test validation.

= 2.6.0 =
Improves malware scanner reliability and progress reporting on hosts with stricter gateway or PHP request timeouts.

= 1.0.6 =
Scanner UI improvements and settings cleanup.

= 1.0.0 =
Initial release of Atomic Edge Security plugin.

== External Services ==

This plugin connects to external services provided by Atomic Edge to deliver WAF, CDN, and security features. Below is a detailed explanation of each service, what data is transmitted, and when.

= Atomic Edge API =

The primary external service this plugin connects to is the Atomic Edge API at `https://dashboard.atomicedge.io/api/v1`.

**What it does:**
* Manages your site's Web Application Firewall (WAF) settings
* Retrieves real-time analytics and traffic data
* Fetches WAF security logs showing blocked threats
* Manages IP whitelist/blacklist and geographic access controls
* Retrieves CDN configuration and status
* Provides vulnerability scanning data for WordPress core, plugins, and themes
* Powers the Adaptive Defense AI-powered threat detection system

**What data is sent:**
* Your site's API key (for authentication)
* IP addresses you add to whitelist/blacklist
* Country codes for geographic blocking rules
* CDN optimization settings (asset types, minification preferences)
* Site URL and domain information
* Adaptive Defense settings and blocked IP information

**When data is sent:**
* When you save settings in the plugin admin pages
* When you view analytics or WAF logs (to fetch data)
* When you run a vulnerability scan
* When you manage IP access control rules
* When Adaptive Defense checks or updates threat status
* Background sync of CDN settings (when CDN is enabled)

**Service links:**
* Service website: [https://atomicedge.io](https://atomicedge.io)
* Terms of Service: [https://atomicedge.io/terms-of-service](https://atomicedge.io/terms-of-service)
* Privacy Policy: [https://atomicedge.io/privacy-policy](https://atomicedge.io/privacy-policy)

= Malware Signature API =

The malware scanner fetches signature patterns from a public API endpoint.

**What it does:**
* Provides up-to-date malware detection signatures
* Allows scanning without requiring an API key

**What data is sent:**
* No personal or site-specific data is sent
* Only a GET request to retrieve signature patterns

**When data is sent:**
* When you initiate a malware scan (if cached signatures have expired)
* Signatures are cached locally for 24 hours

**Service links:**
* This service is provided by Atomic Edge (same terms and privacy policy as above)

= Data Storage =

All API responses are cached locally using WordPress transients to minimize external requests. Malware signature data is cached for 24 hours. Analytics data is fetched fresh on each page load but displayed quickly via JavaScript pagination.
