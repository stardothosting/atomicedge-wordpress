# AtomicEdge WordPress Plugin - Test Suite

This directory contains the automated test suite for the AtomicEdge WordPress plugin.

## Requirements

- PHP 7.4+
- Composer

## Installation

```bash
# Install dependencies
composer install
```

## Running Tests

```bash
# Run all tests
composer test

# Run only unit tests
composer test:unit

# Run only integration tests
composer test:integration

# Run tests with code coverage
composer test:coverage

# Generate HTML coverage report
composer test:coverage-html
```

## Test Structure

```
tests/
├── bootstrap.php              # Test bootstrap and setup
├── TestCase.php               # Base test case class
├── unit/                      # Unit tests (isolated)
│   ├── ApiTest.php            # API class tests
│   ├── AjaxTest.php           # AJAX handler tests
│   ├── ScannerTest.php        # Scanner class tests
│   ├── VulnerabilityScannerTest.php  # Vulnerability scanner tests
│   └── MainPluginTest.php     # Main plugin class tests
└── integration/               # Integration tests
    ├── ConnectionFlowTest.php      # End-to-end flow tests
    └── ApiResponseContractTest.php # API response format validation (CRITICAL)
```

## Test Categories

### 2.9.8 line numbers and compatibility

| Adjustment | Coverage evaluation |
|---|---|
| Line numbers for pattern findings | ScannerTest covers a match on a plain file, CRLF line endings, a match on a final line with no trailing newline, boundary lookup of offset to line, and the one-based line of each match. |
| Distinct lines per pattern | ScannerTest covers repeated matches recording each distinct line in order, and the cap of 10 lines per pattern. |
| Top-level line | ScannerTest confirms the finding's line is the first line of its most severe pattern, not the first match in the file. |
| Hidden PHP in images | ScannerTest confirms the reported line is the first non-XML PHP tag. |
| Results table | A temporary render check of the Scanner page confirmed the "Line N" label, the per-pattern line lists, and that file-level findings show no label. The check was deleted afterward. The automated tests do not render the view. |
| Compatibility | No new WordPress API, option, or AJAX action. The line index is built once per file from the already-capped read, so cost stays linear. Findings stored before 2.9.8 have no line and display as before. |

### 2.9.7 scanner regressions and compatibility

| Adjustment | Coverage evaluation |
|---|---|
| Release untouched claims on time-budget exit | New behavioral tests in `ScannerTest.php`: an expired slice releases every claim, a partially processed batch releases only its tail, and item exceptions still release untouched work. |
| Smaller adaptive batches and step diagnostics | New full-step test checks persisted timing/summary output, current-item processing, discovery state, and bounded adaptive batch size. Existing scan-budget tests remain applicable. |
| Concurrent step ownership | New tests verify that a busy database lock prevents claims and that the connection-owned lock is released after queue errors. The lock is scoped to the WordPress database/table prefix, shared across tabs, and does not rely on expiring transients. |
| Explicit database failures | New tests reject failed reads, empty arrays accompanied by WordPress's `last_error`, and failed completion writes. Existing completion guard still requires zero pending/processing rows. |
| Root-directory resumption | New filesystem-backed test proves an expired slice does not advance its cursor past an unscanned file. |
| Measured discovery ETA | Tests cover withholding the estimate until enough directories are sampled, computing it from measured directory cost, scaling for slice overhead, adding remaining files once file cost is sampled, and accumulating cost totals across steps. |
| Bulk discovery inserts | Tests verify that one directory's children are written in one multi-row statement with duplicate-safe handling, that a failed write leaves the directory unfinished, and that buffered rows flush in bounded chunks. The existing duplicate-path and failure tests remain applicable. |
| Queue counts for ETA | Test separates directories remaining from files remaining, so the discovery estimate uses the correct counts. |
| Context-aware classification | ScannerTest uses temporary files and the mocked signature set. Covered: decode without an execution sink is informational; decode feeding `eval` keeps critical; matches only in comments or string literals are informational; non-.php files keep their severity; the highest severity wins regardless of category order; the finding hash equals the scanned content hash. |
| Unknown-directory calibration | ScannerTest runs the real per-file path: a comment-only match stays low, an executable match is critical, and a PHP file with no match is medium. |
| Sensitivity | ScannerTest covers the default, rejected levels, thresholds, and the open/informational/dismissed state table. AjaxTest covers rejected and persisted levels. |
| Dismissal and restore | ScannerTest uses real files under the WordPress root. Covered: findings must exist in the last results; a changed file is rejected; a dismissal survives a round trip with its reason; restore reinstates the finding; paths outside the root are rejected. Path-only findings receive a content hash. AjaxTest covers unknown actions and dismissals without a scanned finding. |
| Results toolbar | `findings-filter.js`, run from JsSyntaxTest, covers state, status/severity/keyword filters, and severity/file/issue sorting. jQuery DOM wiring is not exercised by automated tests; verify it on a site. |
| Calibration evidence | Verified outside the suite with the real Laravel signature set against the three reported files, using a temporary harness that was deleted afterward. `class-atomicedge-api.php` and `class-atomicedge-2fa-crypto.php`: base64 decoding high → low (`encoding_without_sink`). `admin/views/scanner.php`: keyword medium → low (`inert_context`). |
| Compatibility | Adds one options-backed setting, one dismissal option, two AJAX actions, and `token_get_all()`, which requires the tokenizer extension bundled with PHP. Both options are removed in uninstall. No new WordPress APIs or minimum-version changes. |
| Browser polling | `JsSyntaxTest.php` executes `scanner-polling.js` with Node's built-in assertions: terminal errors stop, gateway retries are bounded, unchanged work pauses, advancing work/cursors continue, completion stops, scan-step requests have a timeout, and progress is never synthetically animated. No npm dependencies or browser/network calls are needed. |
| Release metadata | Version/compatibility declarations are updated together in the plugin entry file and both release readmes; no runtime behavior or minimum requirements change, so no constant-only tests were added. |

Open follow-ups are tracked in the [TODO section of the repository README](../README.md#todo).

Compatibility evaluation (2026-11-17):

- WordPress.org's [download page](https://wordpress.org/download/) and [release archive](https://wordpress.org/download/releases/) list **7.1.4** as the latest stable release. The available local core also reports 7.1.4.
- The scanner continues using core transients, `$wpdb`, AJAX hooks, nonce/capability checks, and JSON response conventions. No newer core-only API is introduced; minimum WordPress 5.8 remains unchanged.
- Queue serialization uses MySQL/MariaDB `GET_LOCK`/`RELEASE_LOCK` without schema changes. The lock is released on normal/error paths and by the database when a nonpersistent connection closes. If locking is unavailable, the scan reports an explicit error rather than proceeding unlocked.
- Run all unit/integration suites with `./vendor/bin/phpunit` and `/usr/bin/php8.2 ./vendor/bin/phpunit`. These suites mock WordPress and database calls; they are **not** a real-core browser/database integration certification.
- Run `./vendor/bin/phpcs --standard=PHPCompatibilityWP --runtime-set testVersion 7.4- --extensions=php --ignore=vendor/*,svn/*,tests/* . -s` for the supported PHP syntax/API range, and `./tests/scan-false-positive-check.sh` for hosting-antivirus regressions.
- Remaining live check: on WordPress 7.1.4, run quick and thorough scans on a disposable/test site, observe queue drainage between slices, attempt a second-tab step, and exercise cancel/resume plus gateway-failure recovery. Compare `step_stats.discovery_ms` per directory item before and after this release on the affected cPanel host (2.9.4-era measurement: about 290 ms per directory item, with 7.2 s of each 8 s step in discovery). Automated timing fixtures do not establish hosting throughput.
- Multi-row `INSERT ... ON DUPLICATE KEY UPDATE id = id` is standard in MySQL 5.x+ and MariaDB 10.x, the versions WordPress recommends. It adds no schema change and uses the existing unique `run_item` key.
- Scanner invariant: normal budget exhaustion must never leave **unstarted** batch items leased; abandoned-work recovery is for interrupted requests only. Keep behavioral tests for this distinction, not just source-string assertions.

### Unit Tests (`tests/unit/`)

Unit tests verify individual components in isolation using Brain/Monkey to mock WordPress functions.

- **ApiTest.php**: Tests for `AtomicEdge_API` class
  - API key encryption/decryption
  - IP validation (IPv4, IPv6, CIDR)
  - Connection/disconnection flow
  - Analytics, WAF logs, IP rules API methods
  - Error handling

- **AjaxTest.php**: Tests for `AtomicEdge_Ajax` class
  - Security validation (nonce, capabilities)
  - Input sanitization
  - All AJAX endpoints

- **ScannerTest.php**: Tests for `AtomicEdge_Scanner` class
  - Pattern detection for malicious code
  - Baseline creation and comparison
  - Scan result persistence

- **MainPluginTest.php**: Tests for `AtomicEdge` class
  - Singleton pattern
  - Component initialization
  - Logging

### Integration Tests (`tests/integration/`)

Integration tests verify that components work together correctly.

- **ConnectionFlowTest.php**: End-to-end connection flows
  - Full connection lifecycle
  - Cache behavior
  - State persistence

- **ApiResponseContractTest.php**: API response format validation (**CRITICAL**)
  - Validates plugin correctly unwraps Laravel API response format
  - Prevents double-nested data bugs
  - Tests AJAX response structure matches JavaScript expectations
  - See "API Response Contract Testing" in Best Practices section

## Writing Tests

### Base Test Case

All tests should extend `AtomicEdge\Tests\TestCase` which provides:

- Brain/Monkey setup/teardown
- Global option/transient storage mocking
- Helper methods for common operations

### Example Test

```php
<?php
namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

class MyClassTest extends TestCase {

    protected function set_up() {
        parent::set_up();
        // Your setup code
    }

    public function test_something() {
        // Mock WordPress functions
        Functions\when('some_wp_function')->justReturn('value');
        
        // Test your code
        $result = my_function();
        
        $this->assertEquals('expected', $result);
    }
}
```

### Mocking WordPress Functions

Use Brain/Monkey to mock WordPress functions:

```php
// Simple return value
Functions\when('get_option')->justReturn('value');

// Custom callback
Functions\when('sanitize_text_field')->alias(function($str) {
    return htmlspecialchars(strip_tags($str));
});

// Expect specific calls
Functions\expect('update_option')
    ->once()
    ->with('my_option', 'my_value')
    ->andReturn(true);
```

### Test Options/Transients

Use the base class helpers:

```php
// Set option for test
$this->set_option('my_option', 'value');

// Get option in test
$value = $this->get_option('my_option');

// Set transient for test
$this->set_transient('my_transient', 'value');
```

## Code Coverage

After running `composer test:coverage-html`, open `tests/coverage/html/index.html` in a browser to view the coverage report.

### Current Coverage (as of 2026-01-07)

| Class | Methods | Lines |
|-------|---------|-------|
| AtomicEdge_API | 76.19% | 96.83% |
| AtomicEdge_Ajax | 25.00% | 66.42% |
| AtomicEdge_Vulnerability_Scanner | 57.14% | 64.37% |
| AtomicEdge_Scanner | 34.62% | 44.32% |
| AtomicEdge | 55.56% | 23.08% |
| **Overall** | **40.00%** | **46.04%** |

### Coverage Goals

- Aim for 80%+ code coverage on core classes
- 100% coverage on security-critical code (API key handling, validation)
- Focus on testing edge cases and error paths

## Best Practices for WordPress Plugin Testing

### 1. Use Brain/Monkey for Mocking
Brain/Monkey is the standard library for mocking WordPress functions in isolated unit tests. It's already configured in this project.

### 2. Define All Required WordPress Constants
The test bootstrap (`bootstrap.php`) must define all WordPress constants your code uses:
- `ABSPATH`, `WPINC`, `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`
- Time constants: `MINUTE_IN_SECONDS`, `HOUR_IN_SECONDS`, `DAY_IN_SECONDS`, etc.
- Encryption constants: `AUTH_KEY`, `SECURE_AUTH_KEY`, `NONCE_KEY`
- Plugin-specific constants: `ATOMICEDGE_VERSION`, `ATOMICEDGE_PLUGIN_DIR`, etc.

### 3. Separate Unit and Integration Tests
- **Unit tests** (`tests/unit/`): Test individual classes in isolation with mocked dependencies
- **Integration tests** (`tests/integration/`): Test how components work together

### 4. Include All Plugin Files in Bootstrap
Every class file must be included in `bootstrap.php`:
```php
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-api.php';
// ... add any new class files here
```

### 5. Reset State Between Tests
The `TestCase` base class automatically resets options and transients between tests. Use the helper methods:
```php
$this->set_option('key', 'value');
$this->get_option('key');
$this->set_transient('key', 'value');
$this->get_transient('key');
$this->clear_transients();
```

### 6. Mock HTTP Requests
Use the provided helpers for testing API calls:
```php
$this->mock_http_success(['data' => 'value'], 200);
$this->mock_http_error('Connection failed');
```

### 7. API Response Contract Testing (CRITICAL)

**Lesson Learned (2026-01-06):** A bug shipped where the API class double-wrapped response data because tests mocked HTTP responses with **incorrect formats** that didn't match the real API.

#### The Problem

The Laravel API returns:
```json
{"success": true, "data": {"total_requests": 1000, ...}}
```

But tests were mocking with:
```json
{"total_requests": 1000, ...}
```

This meant the bug (where `$result['data']` contained `{"success": true, "data": {...}}` instead of just the inner data) was never caught.

#### Best Practices

1. **Always mock with the REAL API response format:**
```php
// WRONG - doesn't match real API
$api_response = ['total_requests' => 1000];
Functions\when('wp_remote_retrieve_body')->justReturn(wp_json_encode($api_response));

// RIGHT - matches real Laravel API format
$api_response = [
    'success' => true,
    'data' => ['total_requests' => 1000],
];
Functions\when('wp_remote_retrieve_body')->justReturn(wp_json_encode($api_response));
```

2. **Test that data is NOT double-nested:**
```php
$result = $api->get_analytics('24h');
$this->assertArrayNotHasKey('success', $result['data'], 'Data should not be double-nested');
```

3. **Simulate AJAX response structure:**
```php
// This is what wp_send_json_success($result['data']) sends
$ajax_response = ['success' => true, 'data' => $result['data']];
$this->assertArrayHasKey('total_requests', $ajax_response['data']);
```

4. **Don't over-mock internal methods:**
```php
// WRONG - bypasses the request() transformation logic
$this->api->method('check_vulnerabilities')->willReturn($mock_result);

// RIGHT - test through the HTTP layer to catch transformation bugs
Functions\when('wp_remote_request')->justReturn([...]);
$result = $api->check_vulnerabilities($data);
```

#### Contract Tests Location

See `tests/integration/ApiResponseContractTest.php` for examples of response format validation.

## Continuous Integration

Tests should be run on:
- Every pull request
- Before merging to main branch
- On release tags

## Troubleshooting

### Tests fail with "Class not found"

Run `composer dump-autoload` to regenerate the autoloader.

### Brain/Monkey errors

Ensure you're calling `parent::set_up()` and `parent::tear_down()` in your test methods.

### Mock not working

Brain/Monkey mocks are reset between tests. Set up mocks in `set_up()` or within each test method.
