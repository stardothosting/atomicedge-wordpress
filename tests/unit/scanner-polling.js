/* Behavioral tests run by JsSyntaxTest using Node's built-in assertion library. */
/* global require, __dirname, console */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
// The fixture path is fixed within this repository, never supplied by a user.
// eslint-disable-next-line security/detect-non-literal-fs-filename
const source = fs.readFileSync(path.join(__dirname, '../../admin/js/admin.js'), 'utf8');

function harness(responses) {
    let now = 0;
    let requests = 0;
    const timers = [];
    const elements = new Map();
    const notices = [];
    function $(selector) {
        const key = String(selector);
        if (!elements.has(key)) {
            elements.set(key, {
                length: 1, value: '', properties: new Map(),
                ready(fn) { fn(); },
                find(child) { return $(key + ' ' + child); },
                prop(name, value) { this.properties.set(name, value); return this; },
                text(value) { if (value === undefined) return this.value; this.value = value; return this; },
                val() { return 'php'; }, is() { return false; },
                show() { return this; }, hide() { return this; }, css() { return this; },
                get() { return {scrollHeight: 0}; }
            });
        }
        return elements.get(key);
    }
    const context = {
        jQuery: $, document: {}, location: {reload() {}},
        Date: {now: () => now}, Math, JSON, parseInt, isNaN,
        setInterval() { assert.fail('Scan progress must not be animated without server evidence'); },
        clearInterval() {}, clearTimeout() {},
        setTimeout(fn) { timers.push(fn); return timers.length; },
        atomicedgeAdmin: {strings: {error: 'Request failed'}, ajaxUrl: '/wp-admin/admin-ajax.php'}
    };
    vm.runInNewContext(source.replace('AtomicEdge.init();', 'globalThis.plugin = AtomicEdge;'), context);
    const plugin = context.plugin;
    const realAjax = plugin.ajax;
    plugin.showNotice = (message) => notices.push(message);
    plugin.ajax = (action, data, success, error) => {
        if (action === 'atomicedge_run_scan') {
            success({run_id: 'test', status: 'running'});
            return;
        }
        requests++;
        const response = responses.shift();
        assert.ok(response, 'Unexpected additional scan request');
        if (response.http_status !== undefined) error(response);
        else success(response);
    };
    return {
        plugin, notices, timers, $, realAjax,
        requests: () => requests,
        advance(ms = 1000) { now += ms; assert.ok(timers.length); timers.shift()(); }
    };
}

const running = () => ({
    status: 'running', stage: 'queue', discovery_complete: false,
    queue_counts: {total: 10, pending: 5, processing: 0, done: 5, directories_remaining: 2},
    results: {scan_stats: {files_total: 20, files_scanned: 5}}
});

{
    const h = harness([{status: 'error', error: 'Database failed'}]);
    h.plugin.runScan();
    assert.equal(h.timers.length, 0);
    assert.match(h.notices[0], /Database failed/);
    assert.equal(h.$('#atomicedge-run-scan').properties.get('disabled'), false);
}
{
    const h = harness(Array.from({length: 6}, () => ({http_status: 504})));
    h.plugin.runScan();
    for (let i = 0; i < 5; i++) h.advance();
    assert.equal(h.requests(), 6);
    assert.equal(h.timers.length, 0);
    assert.equal(h.plugin.state.scan.timeBudget, 4);
    assert.match(h.notices[0], /Repeated connection failures/);
}
{
    const h = harness([running()]);
    h.plugin.runScan();
    const progressText = h.$('#atomicedge-scan-progress .atomicedge-progress-text').value;
    assert.match(progressText, /Discovering: 2 directories left/);
    assert.match(progressText, /ETA: calculating/);
}
{
    const h = harness([Object.assign(running(), {eta_label: '3m 0s'})]);
    h.plugin.runScan();
    assert.match(h.$('#atomicedge-scan-progress .atomicedge-progress-text').value, /ETA: 3m 0s \(estimate, discovery ongoing\)/);
}
{
    const h = harness(Array.from({length: 4}, running));
    h.plugin.runScan();
    for (let i = 0; i < 3; i++) h.advance(60000);
    assert.equal(h.timers.length, 0);
    assert.match(h.notices[0], /No scan progress/);
}
{
    const responses = Array.from({length: 5}, (_, i) => {
        const state = running();
        state.queue_counts.done += i;
        return state;
    });
    const h = harness(responses);
    h.plugin.runScan();
    for (let i = 0; i < 4; i++) h.advance(60000);
    assert.equal(h.notices.length, 0);
    assert.equal(h.timers.length, 1);
}
{
    const responses = Array.from({length: 5}, (_, i) => {
        const state = running();
        state.discovery_cursor = 'large-directory|entry-' + i;
        return state;
    });
    const h = harness(responses);
    h.plugin.runScan();
    for (let i = 0; i < 4; i++) h.advance(60000);
    assert.equal(h.notices.length, 0, 'Directory cursor progress must prevent a false stall');
}
{
    const h = harness([{status: 'complete', progress: 100}]);
    h.plugin.runScan();
    h.advance();
    assert.equal(h.requests(), 1);
    assert.equal(h.timers.length, 0);
}
{
    const h = harness([]);
    let options;
    h.$.ajax = value => { options = value; };
    h.realAjax.call(h.plugin, 'atomicedge_scan_step', {}, () => {}, () => {});
    assert.equal(options.timeout, 60000);
}
console.log('Scanner polling behavior passed.');
