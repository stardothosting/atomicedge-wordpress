/* Behavioral tests run by JsSyntaxTest using Node's built-in assertion library. */
/* global require, __dirname, console */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// The fixture path is fixed within this repository, never supplied by a user.
// eslint-disable-next-line security/detect-non-literal-fs-filename
const source = fs.readFileSync(path.join(__dirname, '../../admin/js/admin.js'), 'utf8');

// Minimal jQuery stand-in: admin.js only needs ready() at load time.
const jQueryStub = () => ({
    ready(fn) { fn(); },
    on() { return this; }
});

const context = {
    jQuery: jQueryStub,
    document: {},
    atomicedgeAdmin: { strings: { error: 'Request failed' }, ajaxUrl: '/wp-admin/admin-ajax.php' },
    console
};
vm.runInNewContext(source.replace('AtomicEdge.init();', 'globalThis.plugin = AtomicEdge;'), context);
const plugin = context.plugin;

// State: dismissed wins; otherwise severity rank against the threshold.
assert.equal(plugin.findingStateFor(2, false, 2), 'open');
assert.equal(plugin.findingStateFor(1, false, 2), 'informational');
assert.equal(plugin.findingStateFor(4, true, 1), 'dismissed');

const open = {
    rank: 3, state: 'open', severity: 'high',
    file: 'wp-content/plugins/x/a.php', issue: 'Base64 decoding', text: 'wp-content/plugins/x/a.php base64 decoding high'
};
const informational = {
    rank: 1, state: 'informational', severity: 'low',
    file: 'includes/b.php', issue: 'Webshell keyword', text: 'includes/b.php webshell keyword low'
};

// Status filter: default "open" hides informational findings.
assert.ok(plugin.findingMatchesFilters(open, { status: 'open', severity: 'all', search: '' }));
assert.ok(!plugin.findingMatchesFilters(informational, { status: 'open', severity: 'all', search: '' }));
assert.ok(plugin.findingMatchesFilters(informational, { status: 'all', severity: 'all', search: '' }));

// Severity filter.
assert.ok(plugin.findingMatchesFilters(informational, { status: 'all', severity: 'low', search: '' }));
assert.ok(!plugin.findingMatchesFilters(open, { status: 'all', severity: 'low', search: '' }));

// Keyword search: every word must match, case-insensitively.
assert.ok(plugin.findingMatchesFilters(open, { status: 'all', severity: 'all', search: '  BASE64   decoding ' }));
assert.ok(!plugin.findingMatchesFilters(open, { status: 'all', severity: 'all', search: 'base64 webshell' }));
assert.ok(plugin.findingMatchesFilters(open, { status: 'all', severity: 'all', search: '' }));

// Sorting: severity (most severe first, then file), file, and issue.
const items = [
    { rank: 1, file: 'a.php', issue: 'z' },
    { rank: 4, file: 'z.php', issue: 'm' },
    { rank: 4, file: 'b.php', issue: 'a' }
];
const sortedBy = (key) => items.slice().sort((x, y) => plugin.compareFindings(x, y, key)).map((item) => item.file);
assert.deepEqual(sortedBy('severity'), ['b.php', 'z.php', 'a.php']);
assert.deepEqual(sortedBy('file'), ['a.php', 'b.php', 'z.php']);
assert.deepEqual(sortedBy('issue'), ['b.php', 'z.php', 'a.php']);

console.log('Findings filter behavior passed.');
