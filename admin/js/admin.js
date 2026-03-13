/**
 * AtomicEdge Admin JavaScript
 *
 * @package AtomicEdge
 */

/* eslint-env browser */
/* global atomicedgeAdmin, Chart, jQuery, document, setTimeout, clearTimeout, setInterval, clearInterval, confirm, alert, location */

(function($) {
    'use strict';

    /**
     * AtomicEdge Admin Module
     */
    var AtomicEdge = {
        /**
         * Charts instances
         */
        charts: {},

        /**
         * Current state
         */
        state: {
            analyticsPage: 1,
            wafPage: 1,
            wafPerPage: 50
        },

        /**
         * Initialize
         */
        init: function() {
            this.bindEvents();
            this.initTabs();
            this.initDashboard();
            this.initAnalytics();
            this.initWafLogs();
            this.initAccessControl();
            this.initScanner();
            this.initSettings();
        },

        /**
         * Bind global events
         */
        bindEvents: function() {
            // Clear cache button
            $('#atomicedge-clear-cache').on('click', this.clearCache.bind(this));
        },

        /**
         * Initialize tabs
         */
        initTabs: function() {
            $('.atomicedge-tabs .nav-tab').on('click', function(e) {
                e.preventDefault();
                var tab = $(this).data('tab');

                // Update active tab
                $('.atomicedge-tabs .nav-tab').removeClass('nav-tab-active');
                $(this).addClass('nav-tab-active');

                // Show tab content
                $('.atomicedge-tab-content').removeClass('atomicedge-tab-active');
                $('#' + tab).addClass('atomicedge-tab-active');
            });

            // Support ?tab= query param to pre-select a tab on page load.
            var params = new URLSearchParams(window.location.search);
            var requestedTab = params.get('tab');
            if (requestedTab) {
                var $target = $('.atomicedge-tabs .nav-tab[data-tab="ip-' + requestedTab + '"]');
                if ($target.length === 0) {
                    $target = $('.atomicedge-tabs .nav-tab[data-tab="' + requestedTab + '"]');
                }
                if ($target.length) {
                    $target.trigger('click');
                }
            }
        },

        /**
         * Initialize dashboard
         */
        initDashboard: function() {
            if ($('#atomicedge-summary-widget').length === 0) {
                return;
            }

            if (atomicedgeAdmin.connected) {
                this.loadDashboardSummary();
            }
        },

        /**
         * Load dashboard summary
         */
        loadDashboardSummary: function() {
            var self = this;

            this.ajax('atomicedge_get_analytics', { period: '24h' }, function(data) {
                var $widget = $('#atomicedge-summary-widget .atomicedge-widget-content');
                $widget.removeClass('atomicedge-loading');

                if (data.total_requests !== undefined) {
                    $widget.html(
                        '<div class="atomicedge-summary-stats">' +
                        '<p><strong>' + atomicedgeAdmin.strings.loading.replace('Loading...', 'Total Requests:') + '</strong> ' + self.formatNumber(data.total_requests) + '</p>' +
                        '<p><strong>Blocked:</strong> ' + self.formatNumber(data.requests_blocked || 0) + '</p>' +
                        '</div>'
                    );

                    // Initialize charts
                    if (data.hourly_data) {
                        self.initDashboardCharts(data.hourly_data);
                    }
                } else {
                    $widget.html('<p class="atomicedge-error">' + atomicedgeAdmin.strings.error + '</p>');
                }
            }, function(errorData) {
                $('#atomicedge-summary-widget .atomicedge-widget-content')
                    .removeClass('atomicedge-loading')
                    .html('<p class="atomicedge-error">' + self.escapeHtml(errorData && errorData.message ? errorData.message : atomicedgeAdmin.strings.error) + '</p>');
            });
        },

        /**
         * Initialize dashboard charts
         */
        initDashboardCharts: function(data) {
            var labels = [];
            var requests = [];
            var blocked = [];

            data.forEach(function(item) {
                labels.push(new Date(item.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                requests.push(item.requests || 0);
                blocked.push(item.blocked || 0);
            });

            // Traffic chart
            var trafficCtx = document.getElementById('atomicedge-traffic-chart');
            if (trafficCtx) {
                this.charts.traffic = new Chart(trafficCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Requests',
                            data: requests,
                            borderColor: '#2271b1',
                            backgroundColor: 'rgba(34, 113, 177, 0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: this.getChartOptions()
                });
            }

            // Attacks chart
            var attacksCtx = document.getElementById('atomicedge-attacks-chart');
            if (attacksCtx) {
                this.charts.attacks = new Chart(attacksCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Blocked',
                            data: blocked,
                            borderColor: '#d63638',
                            backgroundColor: 'rgba(214, 54, 56, 0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: this.getChartOptions()
                });
            }
        },

        /**
         * Initialize analytics page
         */
        initAnalytics: function() {
            var self = this;

            if ($('#atomicedge-period').length === 0) {
                return;
            }

            // Period change
            $('#atomicedge-period').on('change', function() {
                self.loadAnalytics($(this).val());
            });

            // Refresh button
            $('#atomicedge-refresh-analytics').on('click', function() {
                self.loadAnalytics($('#atomicedge-period').val());
            });

            // Initial load
            this.loadAnalytics('24h');
        },

        /**
         * Load analytics data
         */
        loadAnalytics: function(period) {
            var self = this;

            $('#atomicedge-analytics-loading').show();
            $('#atomicedge-analytics-error').hide();

            this.ajax('atomicedge_get_analytics', { period: period }, function(data) {
                $('#atomicedge-analytics-loading').hide();
                self.updateAnalyticsStats(data);
                self.updateAnalyticsCharts(data.hourly_data || []);
            }, function(errorData) {
                $('#atomicedge-analytics-loading').hide();
                if (errorData && errorData.message) {
                    $('#atomicedge-analytics-error').find('span').last().text(errorData.message);
                }
                $('#atomicedge-analytics-error').show();
            });
        },

        /**
         * Update analytics stats
         */
        updateAnalyticsStats: function(data) {
            $('#stat-total-requests').text(this.formatNumber(data.total_requests || 0));
            $('#stat-unique-visitors').text(this.formatNumber(data.unique_visitors || 0));
            $('#stat-blocked-requests').text(this.formatNumber(data.requests_blocked || 0));

            var blockRate = data.total_requests > 0 
                ? ((data.requests_blocked / data.total_requests) * 100).toFixed(1) + '%'
                : '0%';
            $('#stat-block-rate').text(blockRate);
        },

        /**
         * Update analytics charts
         */
        updateAnalyticsCharts: function(data) {
            var labels = [];
            var requests = [];
            var blocked = [];

            data.forEach(function(item) {
                labels.push(new Date(item.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                requests.push(item.requests || 0);
                blocked.push(item.blocked || 0);
            });

            // Destroy existing charts
            if (this.charts.analyticsTraffic) {
                this.charts.analyticsTraffic.destroy();
            }
            if (this.charts.analyticsBlocked) {
                this.charts.analyticsBlocked.destroy();
            }

            // Traffic chart
            var trafficCtx = document.getElementById('atomicedge-traffic-chart');
            if (trafficCtx) {
                this.charts.analyticsTraffic = new Chart(trafficCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Requests',
                            data: requests,
                            borderColor: '#2271b1',
                            backgroundColor: 'rgba(34, 113, 177, 0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: this.getChartOptions()
                });
            }

            // Blocked chart
            var blockedCtx = document.getElementById('atomicedge-blocked-chart');
            if (blockedCtx) {
                this.charts.analyticsBlocked = new Chart(blockedCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Blocked',
                            data: blocked,
                            borderColor: '#d63638',
                            backgroundColor: 'rgba(214, 54, 56, 0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: this.getChartOptions()
                });
            }
        },

        /**
         * Initialize WAF logs page
         */
        initWafLogs: function() {
            var self = this;

            if ($('#atomicedge-waf-table').length === 0) {
                return;
            }

            // Search
            var searchTimeout;
            $('#atomicedge-waf-search').on('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(function() {
                    self.state.wafPage = 1;
                    self.loadWafLogs();
                }, 500);
            });

            // Per page change
            $('#atomicedge-waf-per-page').on('change', function() {
                self.state.wafPerPage = parseInt($(this).val(), 10);
                self.state.wafPage = 1;
                self.loadWafLogs();
            });

            // Refresh
            $('#atomicedge-waf-refresh').on('click', function() {
                self.loadWafLogs();
            });

            // Pagination
            $('#atomicedge-waf-prev').on('click', function() {
                if (self.state.wafPage > 1) {
                    self.state.wafPage--;
                    self.loadWafLogs();
                }
            });

            $('#atomicedge-waf-next').on('click', function() {
                self.state.wafPage++;
                self.loadWafLogs();
            });

            // Initial load
            this.loadWafLogs();
        },

        /**
         * Load WAF logs
         */
        loadWafLogs: function() {
            var self = this;
            var $tbody = $('#atomicedge-waf-logs-body');

            $tbody.html('<tr class="atomicedge-loading-row"><td colspan="6"><span class="spinner is-active"></span> ' + atomicedgeAdmin.strings.loading + '</td></tr>');
            $('#atomicedge-waf-no-results').hide();
            $('#atomicedge-waf-error').hide();

            this.ajax('atomicedge_get_waf_logs', {
                page: this.state.wafPage,
                per_page: this.state.wafPerPage,
                search: $('#atomicedge-waf-search').val() || ''
            }, function(data) {
                self.renderWafLogs(data);
            }, function() {
                $tbody.empty();
                $('#atomicedge-waf-error').show();
            });
        },

        /**
         * Render WAF logs table
         */
        renderWafLogs: function(data) {
            var $tbody = $('#atomicedge-waf-logs-body');
            $tbody.empty();

            var logs = data.logs || [];

            if (logs.length === 0) {
                $('#atomicedge-waf-no-results').show();
                return;
            }

            var self = this;
            logs.forEach(function(log) {
                var actionCell;
                if (log.is_blocked) {
                    actionCell = '<span class="atomicedge-blocked-badge" title="This IP is blocked" style="color:#b32d2e;font-weight:600;">' +
                        '<span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;margin-top:3px;"></span> Blocked</span>';
                } else {
                    actionCell = '<button type="button" class="button button-small atomicedge-block-ip" data-ip="' + self.escapeHtml(log.client_ip || '') + '">Block IP</button>';
                }
                var row = '<tr>' +
                    '<td>' + self.escapeHtml(log.event_timestamp || '') + '</td>' +
                    '<td><code>' + self.escapeHtml(log.client_ip || '') + '</code></td>' +
                    '<td>' + self.escapeHtml(log.uri || '').substring(0, 50) + '</td>' +
                    '<td><code>' + self.escapeHtml(log.waf_rule_id || '') + '</code></td>' +
                    '<td>' + self.escapeHtml(log.group || '') + '</td>' +
                    '<td>' + actionCell + '</td>' +
                    '</tr>';
                $tbody.append(row);
            });

            // Bind block IP buttons — blocks go to Adaptive Defense (not IP blacklist).
            $tbody.find('.atomicedge-block-ip').on('click', function() {
                var $btn = $(this);
                var ip = $btn.data('ip');
                if (confirm(atomicedgeAdmin.strings.confirm)) {
                    self.blockIpFromWafLogs(ip, $btn);
                }
            });

            // Update pagination
            $('#atomicedge-waf-page-info').text('Page ' + this.state.wafPage);
            $('#atomicedge-waf-prev').prop('disabled', this.state.wafPage <= 1);
            $('#atomicedge-waf-next').prop('disabled', logs.length < this.state.wafPerPage);
        },

        /**
         * Initialize access control page
         */
        initAccessControl: function() {
            var self = this;

            if ($('#atomicedge-whitelist-table').length === 0) {
                return;
            }

            // Load IP rules
            this.loadIpRules();

            // Whitelist form
            $('#atomicedge-add-whitelist-form').on('submit', function(e) {
                e.preventDefault();
                var ip = $('#whitelist-ip').val();
                var desc = $('#whitelist-description').val();

                if (!self.validateIp(ip)) {
                    self.showNotice(atomicedgeAdmin.strings.invalidIp, 'error');
                    return;
                }

                self.addIpWhitelist(ip, desc);
            });

            // Blacklist form
            $('#atomicedge-add-blacklist-form').on('submit', function(e) {
                e.preventDefault();
                var ip = $('#blacklist-ip').val();
                var desc = $('#blacklist-description').val();

                if (!self.validateIp(ip)) {
                    self.showNotice(atomicedgeAdmin.strings.invalidIp, 'error');
                    return;
                }

                self.addIpBlacklist(ip, desc);
            });

            // Geo form
            $('#geo-enabled').on('change', function() {
                $('#geo-options').toggle($(this).is(':checked'));
            });

            // Load geo rules
            this.loadGeoRules();

            // Geo form submit
            $('#atomicedge-geo-form').on('submit', function(e) {
                e.preventDefault();
                self.updateGeoRules();
            });
        },

        /**
         * Load IP rules
         *
         * @param {boolean} forceRefresh Bypass transient cache (default true)
         */
        loadIpRules: function(forceRefresh) {
            var self = this;
            var data = {};

            if (forceRefresh !== false) {
                data.force_refresh = 'true';
            }

            this.ajax('atomicedge_get_ip_rules', data, function(data) {
                self.renderIpList('whitelist', data.whitelist || []);
                self.renderIpList('blacklist', data.blacklist || []);
            });
        },

        /**
         * Parse source label from a blacklist description.
         *
         * @param  {string} description e.g. "Blocked from WAF logs on 2026-02-27 14:35 UTC"
         * @return {string} e.g. "WAF Logs" or "Manual"
         */
        parseBlockSource: function(description) {
            if (!description) {
                return 'Manual';
            }
            var lower = description.toLowerCase();
            if (lower.indexOf('waf log') !== -1)              return 'WAF Logs';
            if (lower.indexOf('actor profile') !== -1)        return 'Actor Profiles';
            if (lower.indexOf('threat detection') !== -1)     return 'Threat Detections';
            if (lower.indexOf('adaptive defense') !== -1)     return 'Adaptive Defense';
            return 'Manual';
        },

        /**
         * Render IP list
         */
        renderIpList: function(type, ips) {
            var $tbody = $('#atomicedge-' + type + '-body');
            var isBlacklist = (type === 'blacklist');
            var cols = isBlacklist ? 4 : 3;
            $tbody.empty();

            if (ips.length === 0) {
                $tbody.html('<tr><td colspan="' + cols + '">No IPs in ' + type + '</td></tr>');
                return;
            }

            var self = this;
            ips.forEach(function(item) {
                var sourceCell = '';
                if (isBlacklist) {
                    var sourceLabel = self.parseBlockSource(item.description);
                    var badgeClass = 'atomicedge-source-manual';
                    if (sourceLabel === 'WAF Logs')           badgeClass = 'atomicedge-source-waf';
                    if (sourceLabel === 'Actor Profiles')     badgeClass = 'atomicedge-source-actor';
                    if (sourceLabel === 'Threat Detections')  badgeClass = 'atomicedge-source-detection';
                    if (sourceLabel === 'Adaptive Defense')   badgeClass = 'atomicedge-source-ad';
                    sourceCell = '<td><span class="atomicedge-source-badge ' + badgeClass + '">' + self.escapeHtml(sourceLabel) + '</span></td>';
                }
                var row = '<tr>' +
                    '<td><code>' + self.escapeHtml(item.ip) + '</code></td>' +
                    sourceCell +
                    '<td>' + self.escapeHtml(item.description || '') + '</td>' +
                    '<td><button type="button" class="button button-small atomicedge-remove-ip" data-ip="' + self.escapeHtml(item.ip) + '" data-type="' + type + '">Remove</button></td>' +
                    '</tr>';
                $tbody.append(row);
            });

            // Bind remove buttons
            $tbody.find('.atomicedge-remove-ip').on('click', function() {
                var ip = $(this).data('ip');
                var ipType = $(this).data('type');
                if (confirm(atomicedgeAdmin.strings.confirmIp)) {
                    self.removeIp(ip, ipType);
                }
            });
        },

        /**
         * Add IP to whitelist
         */
        addIpWhitelist: function(ip, description) {
            var self = this;
            this.ajax('atomicedge_add_ip_whitelist', { ip: ip, description: description }, function() {
                $('#whitelist-ip').val('');
                $('#whitelist-description').val('');
                self.loadIpRules();
            });
        },

        /**
         * Block an IP from the WAF logs page via Adaptive Defense.
         *
         * This sends the block to the AD system (ActorProfile), NOT the
         * Access Control IP blacklist (SiteSettings).  The existing
         * ajax_block_ip AJAX handler + api->block_ip() method are reused.
         *
         * @param {string} ip      IP address.
         * @param {jQuery} $button The button element to update on success.
         */
        blockIpFromWafLogs: function(ip, $button) {
            var self = this;

            if ($button) {
                $button.prop('disabled', true).text(atomicedgeAdmin.strings.loading);
            }

            this.ajax('atomicedge_block_ip', {
                ip: ip,
                reason: 'Blocked from WAF logs'
            }, function() {
                // Reload WAF logs so the is_blocked badge appears.
                if ($('#atomicedge-waf-table').length) {
                    self.loadWafLogs();
                }

                // Immediate visual feedback.
                if ($button) {
                    $button.prop('disabled', true)
                        .removeClass('button-small')
                        .addClass('atomicedge-blocked-btn')
                        .html('<span class="dashicons dashicons-yes-alt" style="margin-top:3px;color:#00a32a;"></span> Blocked');
                }

                self.showNotice(ip + ' has been blocked via Adaptive Defense.', 'success');
            }, function(errData) {
                if ($button) {
                    $button.prop('disabled', false).text('Block IP');
                }
                var message = (errData && errData.message) ? errData.message : atomicedgeAdmin.strings.error;
                self.showNotice(message, 'error');
            });
        },

        /**
         * Add IP to blacklist (Access Control page only).
         *
         * @param {string}  ip          IP address or CIDR.
         * @param {string}  description Optional description.
         * @param {jQuery}  $button     Optional button element to update on success.
         */
        addIpBlacklist: function(ip, description, $button) {
            var self = this;

            if ($button) {
                $button.prop('disabled', true).text(atomicedgeAdmin.strings.loading);
            }

            this.ajax('atomicedge_add_ip_blacklist', { ip: ip, description: description }, function() {
                // Clear form fields if on access control page.
                $('#blacklist-ip').val('');
                $('#blacklist-description').val('');
                self.loadIpRules();

                // If on WAF logs page, reload the table so is_blocked badges
                // reflect the authoritative server state (cache was invalidated
                // server-side by the add_ip_blacklist API call).
                if ($('#atomicedge-waf-table').length) {
                    self.loadWafLogs();
                }

                // Update button to show blocked state (immediate feedback before
                // the WAF logs reload finishes).
                if ($button) {
                    $button.prop('disabled', true)
                        .removeClass('button-small')
                        .addClass('atomicedge-blocked-btn')
                        .html('<span class="dashicons dashicons-yes-alt" style="margin-top:3px;color:#00a32a;"></span> Blocked');
                }

                var noticeMsg = ip + ' has been added to the IP blacklist.';
                self.showNotice(noticeMsg, 'success');
            }, function(errData) {
                if ($button) {
                    $button.prop('disabled', false).text('Add to Blacklist');
                }
                var message = (errData && errData.message) ? errData.message : atomicedgeAdmin.strings.error;
                self.showNotice(message, 'error');
            });
        },

        /**
         * Format current date/time as a human-readable timestamp.
         *
         * @return {string} e.g. "2026-02-27 14:35 UTC"
         */
        formatTimestamp: function() {
            var d = new Date();
            var pad = function(n) { return n < 10 ? '0' + n : n; };
            return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) +
                ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ' UTC';
        },

        /**
         * Remove IP
         */
        removeIp: function(ip, type) {
            var self = this;
            this.ajax('atomicedge_remove_ip', { ip: ip, type: type }, function() {
                self.loadIpRules();
                self.showNotice(self.escapeHtml(ip) + ' has been removed from the ' + self.escapeHtml(type) + '.', 'success');
            });
        },

        /**
         * Load geo rules
         */
        loadGeoRules: function() {
            // Populate countries list
            this.populateCountries();

            this.ajax('atomicedge_get_geo_rules', {}, function(data) {
                $('#geo-enabled').prop('checked', data.enabled || false);
                $('#geo-mode').val(data.mode || 'blacklist');
                
                if (data.countries && data.countries.length) {
                    $('#geo-countries').val(data.countries);
                }

                $('#geo-options').toggle(data.enabled || false);
            });
        },

        /**
         * Populate countries dropdown
         */
        populateCountries: function() {
            var countries = {
                'AF': 'Afghanistan', 'AL': 'Albania', 'DZ': 'Algeria', 'AR': 'Argentina',
                'AU': 'Australia', 'AT': 'Austria', 'BE': 'Belgium', 'BR': 'Brazil',
                'CA': 'Canada', 'CN': 'China', 'CO': 'Colombia', 'CZ': 'Czech Republic',
                'DK': 'Denmark', 'EG': 'Egypt', 'FI': 'Finland', 'FR': 'France',
                'DE': 'Germany', 'GR': 'Greece', 'HK': 'Hong Kong', 'HU': 'Hungary',
                'IN': 'India', 'ID': 'Indonesia', 'IR': 'Iran', 'IQ': 'Iraq',
                'IE': 'Ireland', 'IL': 'Israel', 'IT': 'Italy', 'JP': 'Japan',
                'KR': 'South Korea', 'KP': 'North Korea', 'MY': 'Malaysia', 'MX': 'Mexico',
                'NL': 'Netherlands', 'NZ': 'New Zealand', 'NG': 'Nigeria', 'NO': 'Norway',
                'PK': 'Pakistan', 'PH': 'Philippines', 'PL': 'Poland', 'PT': 'Portugal',
                'RO': 'Romania', 'RU': 'Russia', 'SA': 'Saudi Arabia', 'SG': 'Singapore',
                'ZA': 'South Africa', 'ES': 'Spain', 'SE': 'Sweden', 'CH': 'Switzerland',
                'TW': 'Taiwan', 'TH': 'Thailand', 'TR': 'Turkey', 'UA': 'Ukraine',
                'AE': 'United Arab Emirates', 'GB': 'United Kingdom', 'US': 'United States',
                'VN': 'Vietnam'
            };

            var $select = $('#geo-countries');
            $.each(countries, function(code, name) {
                $select.append('<option value="' + code + '">' + name + ' (' + code + ')</option>');
            });
        },

        /**
         * Update geo rules
         */
        updateGeoRules: function() {
            var data = {
                enabled: $('#geo-enabled').is(':checked') ? 'true' : 'false',
                mode: $('#geo-mode').val(),
                countries: $('#geo-countries').val() || []
            };

            this.ajax('atomicedge_update_geo_rules', data, function() {
                alert(atomicedgeAdmin.strings.success);
            });
        },

        /**
         * Initialize scanner page (malware scanner)
         */
        initScanner: function() {
            var self = this;

            // Initialize pagination for results tables (works on both scanner pages)
            this.initScannerPagination();

            // Malware scan button
            if ($('#atomicedge-run-scan').length > 0) {
                $('#atomicedge-run-scan').on('click', function() {
                    self.runScan();
                });
            }

            if ($('#atomicedge-cancel-scan').length > 0) {
                $('#atomicedge-cancel-scan').on('click', function() {
                    self.cancelScan();
                });
            }

            if ($('#atomicedge-reset-scan').length > 0) {
                $('#atomicedge-reset-scan').on('click', function() {
                    self.resetScan();
                });
            }

            // Vulnerability scanner button (on separate page)
            if ($('#atomicedge-run-vuln-scan').length > 0) {
                $('#atomicedge-run-vuln-scan').on('click', function() {
                    self.runVulnerabilityScan();
                });
            }

            if ($('#atomicedge-reset-vuln-results').length > 0) {
                $('#atomicedge-reset-vuln-results').on('click', function() {
                    self.resetVulnerabilityResults();
                });
            }

            if ($('.atomicedge-vuln-filter').length > 0) {
                self.initVulnerabilitySeverityFilters();
            }

            // Debug test button (only present when WP_DEBUG is true)
            if ($('#atomicedge-debug-test').length > 0) {
                $('#atomicedge-debug-test').on('click', function() {
                    self.runDebugTest();
                });
            }
        },

        /**
         * Run debug scan test (500 files) - only visible when WP_DEBUG is true.
         */
        runDebugTest: function() {
            var self = this;
            var $button = $('#atomicedge-debug-test');
            var $results = $('#atomicedge-debug-results');
            var $output = $('#atomicedge-debug-output');

            if ($button.prop('disabled')) {
                return;
            }

            $button.prop('disabled', true).text('Testing...');
            $results.show();
            $output.text('Running debug scan on 500 files...\n');

            this.ajax('atomicedge_scan_debug_test', {}, function(data) {
                $button.prop('disabled', false).text('Debug Test (500 files)');
                
                // Format and display results
                var output = '=== Debug Scan Results ===\n\n';
                output += 'Files Found: ' + (data.files_found || 0) + '\n';
                output += 'Files Scanned: ' + (data.files_scanned || 0) + '\n';
                output += 'Quick Rejected: ' + (data.files_quick_rejected || 0) + '\n';
                output += 'Regex Scanned: ' + (data.files_regex_scanned || 0) + '\n';
                output += 'Quick Rejection Rate: ' + (data.quick_rejection_rate || 'N/A') + '\n\n';
                
                if (data.timing) {
                    output += '--- Timing ---\n';
                    output += 'Enumeration: ' + (data.timing.enumeration_ms || 0) + ' ms\n';
                    output += 'Scanning: ' + (data.timing.scanning_ms || 0) + ' ms\n';
                    output += 'Total: ' + (data.timing.total_seconds || 0) + ' seconds\n';
                }
                
                if (data.files_per_second) {
                    output += 'Rate: ' + data.files_per_second + ' files/sec\n';
                }
                
                if (data.issues_found && data.issues_found.length > 0) {
                    output += '\n--- Issues Found: ' + data.issues_found.length + ' ---\n';
                    data.issues_found.slice(0, 10).forEach(function(issue) {
                        output += '  ' + self.escapeHtml(issue.file) + ' (' + self.escapeHtml(issue.type) + ')\n';
                    });
                    if (data.issues_found.length > 10) {
                        output += '  ... and ' + (data.issues_found.length - 10) + ' more\n';
                    }
                } else {
                    output += '\nNo issues found.\n';
                }
                
                if (data.server_info) {
                    output += '\n--- Server Info ---\n';
                    output += 'PHP: ' + (data.server_info.php_version || 'N/A') + '\n';
                    output += 'Max Execution: ' + (data.server_info.max_execution_time || 'N/A') + 's\n';
                    output += 'Memory Limit: ' + (data.server_info.memory_limit || 'N/A') + '\n';
                }
                
                $output.text(output);
            }, function(err) {
                $button.prop('disabled', false).text('Debug Test (500 files)');
                $output.text('Error: ' + self.escapeHtml((err && err.message) ? err.message : 'Unknown error'));
            });
        },

        /**
         * Initialize settings page
         */
        initSettings: function() {
            // Settings page initialization
            // WPScan token functionality removed - vulnerability scanning now uses AtomicEdge API
        },

        /**
         * Run vulnerability scan
         */
        runVulnerabilityScan: function() {
            var $button = $('#atomicedge-run-vuln-scan');
            var $progress = $('#atomicedge-vuln-progress');

            $button.prop('disabled', true);
            $progress.show();

            // Animate progress bar
            var $progressFill = $progress.find('.atomicedge-progress-fill');
            $progressFill.css('width', '0%');
            
            var progress = 0;
            var progressInterval = setInterval(function() {
                progress = Math.min(progress + Math.random() * 8, 90);
                $progressFill.css('width', progress + '%');
            }, 600);

            this.ajax('atomicedge_run_vulnerability_scan', { force_refresh: 'true' }, function() {
                clearInterval(progressInterval);
                $progressFill.css('width', '100%');
                
                setTimeout(function() {
                    $progress.hide();
                    $button.prop('disabled', false);
                    // Reload page to show results
                    location.reload();
                }, 500);
            }, function(data) {
                clearInterval(progressInterval);
                $progress.hide();
                $button.prop('disabled', false);
                
                if (data && data.rate_limited) {
                    // Show the persistent rate-limit notice in the page.
                    $('#atomicedge-vuln-rate-limit-notice').show();
                } else {
                    alert(data.message || atomicedgeAdmin.strings.error);
                }
            });
        },

        /**
         * Reset vulnerability scan results (options + transient).
         */
        resetVulnerabilityResults: function() {
            var $resetButton = $('#atomicedge-reset-vuln-results');

            if ($resetButton.prop('disabled')) {
                return;
            }

            if (!confirm('Reset vulnerability scan results? This will clear saved results.')) {
                return;
            }

            $resetButton.prop('disabled', true);

            this.ajax('atomicedge_reset_vulnerability_results', {}, function() {
                location.reload();
            }, function(err) {
                $resetButton.prop('disabled', false);
                alert((err && err.message) ? err.message : atomicedgeAdmin.strings.error);
            });
        },

        /**
         * Client-side severity filtering for vulnerability items.
         */
        initVulnerabilitySeverityFilters: function() {
            var applyFilters = function() {
                var allowed = {};
                $('.atomicedge-vuln-filter:checked').each(function() {
                    allowed[$(this).val()] = true;
                });

                $('.atomicedge-vuln-item').each(function() {
                    var $item = $(this);
                    var match = false;

                    for (var sev in allowed) {
                        if (Object.prototype.hasOwnProperty.call(allowed, sev) && $item.hasClass('atomicedge-severity-' + sev)) {
                            match = true;
                            break;
                        }
                    }

                    $item.toggle(match);
                });
            };

            $('.atomicedge-vuln-filter').on('change', function() {
                applyFilters();
            });

            applyFilters();
        },

        /**
         * Initialize pagination for scanner results tables
         */
        initScannerPagination: function() {
            var self = this;
            
            $('[data-paginate="true"]').each(function() {
                var $section = $(this);
                var $table = $section.find('.atomicedge-paginated-table');
                var $pagination = $section.find('.atomicedge-pagination');
                var perPage = parseInt($section.data('per-page'), 10) || 10;
                var $rows = $table.find('tbody tr');
                var totalRows = $rows.length;
                var totalPages = Math.ceil(totalRows / perPage);
                
                if (totalPages <= 1) {
                    return; // No pagination needed
                }
                
                // Store pagination state
                $section.data('currentPage', 1);
                $section.data('totalPages', totalPages);
                $section.data('perPage', perPage);
                
                // Build pagination UI
                self.buildPaginationUI($section, $pagination, totalRows, perPage, totalPages);
                
                // Show first page
                self.showPage($section, 1);
            });
        },

        /**
         * Build pagination UI
         */
        buildPaginationUI: function($section, $pagination, totalRows, perPage, totalPages) {
            var self = this;
            var html = '<div class="atomicedge-pagination-info">';
            html += 'Showing <span class="showing-start">1</span>-<span class="showing-end">' + Math.min(perPage, totalRows) + '</span> of ' + totalRows + ' items';
            html += '</div>';
            html += '<div class="atomicedge-pagination-buttons">';
            html += '<button type="button" class="button pagination-prev" disabled>&laquo; Prev</button>';
            
            for (var i = 1; i <= totalPages; i++) {
                html += '<button type="button" class="button pagination-page' + (i === 1 ? ' current' : '') + '" data-page="' + i + '">' + i + '</button>';
            }
            
            html += '<button type="button" class="button pagination-next"' + (totalPages <= 1 ? ' disabled' : '') + '>Next &raquo;</button>';
            html += '</div>';
            
            $pagination.html(html);
            
            // Bind events
            $pagination.find('.pagination-prev').on('click', function() {
                var currentPage = $section.data('currentPage');
                if (currentPage > 1) {
                    self.showPage($section, currentPage - 1);
                }
            });
            
            $pagination.find('.pagination-next').on('click', function() {
                var currentPage = $section.data('currentPage');
                var totalPages = $section.data('totalPages');
                if (currentPage < totalPages) {
                    self.showPage($section, currentPage + 1);
                }
            });
            
            $pagination.find('.pagination-page').on('click', function() {
                var page = parseInt($(this).data('page'), 10);
                self.showPage($section, page);
            });
        },

        /**
         * Show specific page of results
         */
        showPage: function($section, page) {
            var $table = $section.find('.atomicedge-paginated-table');
            var $pagination = $section.find('.atomicedge-pagination');
            var perPage = $section.data('perPage');
            var totalPages = $section.data('totalPages');
            var $rows = $table.find('tbody tr');
            var totalRows = $rows.length;
            
            // Update current page
            $section.data('currentPage', page);
            
            // Show/hide rows
            var startIndex = (page - 1) * perPage;
            var endIndex = startIndex + perPage;
            
            $rows.each(function(index) {
                if (index >= startIndex && index < endIndex) {
                    $(this).removeClass('hidden-row');
                } else {
                    $(this).addClass('hidden-row');
                }
            });
            
            // Update pagination info
            $pagination.find('.showing-start').text(startIndex + 1);
            $pagination.find('.showing-end').text(Math.min(endIndex, totalRows));
            
            // Update button states
            $pagination.find('.pagination-prev').prop('disabled', page === 1);
            $pagination.find('.pagination-next').prop('disabled', page === totalPages);
            $pagination.find('.pagination-page').removeClass('current');
            $pagination.find('.pagination-page[data-page="' + page + '"]').addClass('current');
        },

        /**
         * Run malware scan
         */
        runScan: function() {
            var self = this;
            var $button = $('#atomicedge-run-scan');
            var $cancelButton = $('#atomicedge-cancel-scan');
            var $resetButton = $('#atomicedge-reset-scan');
            var $mode = $('#atomicedge-scan-mode');
            var $verifyIntegrity = $('#atomicedge-verify-integrity');
            var $progress = $('#atomicedge-scan-progress');
            var $results = $('#atomicedge-scan-results');
            var $logSection = $('#atomicedge-scan-log');
            var $logLines = $logSection.find('.atomicedge-scan-log-lines');
            var $progressText = $progress.find('.atomicedge-progress-text');

            var hasRealProgress = false;
            var lastDisplayedProgress = 0;

            if (!this.state.scan) {
                this.state.scan = {};
            }
            this.state.scan.cancelled = false;
            this.state.scan.runId = null;
            this.state.scan.pollTimeout = null;
            this.state.scan.progressInterval = null;

            $button.prop('disabled', true);
            $cancelButton.prop('disabled', false);
            $resetButton.prop('disabled', true);
            $progress.show();
            $results.hide();
            $logSection.show();
            $logLines.text('');

            // Animate progress bar until we get real progress values.
            var $progressFill = $progress.find('.atomicedge-progress-fill');
            $progressFill.css('width', '0%');
            
            var progress = 0;
            var progressInterval = setInterval(function() {
                progress = Math.min(progress + Math.random() * 10, 90);
                lastDisplayedProgress = Math.max(lastDisplayedProgress, progress);
                $progressFill.css('width', lastDisplayedProgress + '%');
            }, 500);

            this.state.scan.progressInterval = progressInterval;

            var runId = null;

            var renderStatus = function(stepData) {
                if (!stepData) {
                    return;
                }

                if (stepData.progress !== undefined) {
                    var p = parseInt(stepData.progress, 10);
                    if (!isNaN(p)) {
                        if (!hasRealProgress) {
                            hasRealProgress = true;
                            clearInterval(progressInterval);
                        }

                        p = Math.min(Math.max(p, 0), 100);
                        lastDisplayedProgress = Math.max(lastDisplayedProgress, p);
                        $progressFill.css('width', lastDisplayedProgress + '%');
                    }
                }

                var stage = stepData.stage || '';
                var currentItem = stepData.current_item || null;
                var scanMode = stepData.scan_mode || '';
                var scanStats = stepData.results && stepData.results.scan_stats ? stepData.results.scan_stats : null;

                var parts = [];
                if (stage) {
                    parts.push('Stage: ' + stage);
                }
                if (scanMode) {
                    parts.push('Mode: ' + scanMode);
                }
                if (scanStats && scanStats.files_total) {
                    var scannedCount = parseInt(scanStats.files_scanned || 0, 10);
                    var totalCount = parseInt(scanStats.files_total || 0, 10);
                    var remainingCount = Math.max(0, totalCount - scannedCount);
                    parts.push('Files: ' + scannedCount + '/' + totalCount);
                    parts.push('Remaining: ' + remainingCount);
                }
                if (currentItem && currentItem.path) {
                    parts.push('Now: ' + currentItem.path);
                }
                if (stepData.eta_label) {
                    parts.push('ETA: ' + stepData.eta_label);
                } else if (scanStats && scanStats.files_total) {
                    parts.push('ETA: calculating...');
                }
                if (parts.length) {
                    $progressText.text(parts.join(' · '));
                }

                if (stepData.log && Array.isArray(stepData.log) && stepData.log.length) {
                    $logLines.text(stepData.log.join('\n'));
                    var el = $logLines.get(0);
                    if (el && el.scrollHeight !== undefined) {
                        el.scrollTop = el.scrollHeight;
                    }
                }
            };

            var pollStep = function() {
                if (self.state.scan && self.state.scan.cancelled) {
                    return;
                }
                self.ajax('atomicedge_scan_step', { run_id: runId || '' }, function(stepData) {
                    renderStatus(stepData);

                    if (stepData && stepData.status === 'complete') {
                        clearInterval(progressInterval);
                        lastDisplayedProgress = 100;
                        $progressFill.css('width', '100%');
                        setTimeout(function() {
                            $progress.hide();
                            $logSection.hide();
                            $button.prop('disabled', false);
                            $cancelButton.prop('disabled', true);
                            $resetButton.prop('disabled', false);
                            location.reload();
                        }, 500);
                        return;
                    }

                    // Adaptive polling: wait a fraction of the server's time budget.
                    // For short budgets (5s), poll quickly (300ms).
                    // For longer budgets (20s), poll less frequently (800ms).
                    var timeBudget = stepData && stepData.time_budget ? parseInt(stepData.time_budget, 10) : 8;
                    var pollDelay = Math.min(800, Math.max(300, timeBudget * 40));
                    self.state.scan.pollTimeout = setTimeout(pollStep, pollDelay);
                }, function(err) {
                    clearInterval(progressInterval);
                    $progress.hide();
                    $logSection.hide();
                    $button.prop('disabled', false);
                    $cancelButton.prop('disabled', true);
                    $resetButton.prop('disabled', false);
                    alert((err && err.message) ? err.message : atomicedgeAdmin.strings.error);
                });
            };

            var selectedMode = ($mode.length ? String($mode.val() || '') : '');
            if (selectedMode !== 'php' && selectedMode !== 'all') {
                selectedMode = 'all';
            }

            var verifyIntegrity = ($verifyIntegrity.length && $verifyIntegrity.is(':checked')) ? 1 : 0;

            this.ajax('atomicedge_run_scan', { scan_mode: selectedMode, verify_integrity: verifyIntegrity }, function(data) {
                runId = data && data.run_id ? data.run_id : null;
                if (self.state.scan) {
                    self.state.scan.runId = runId;
                }
                renderStatus(data);
                pollStep();
            }, function(err) {
                clearInterval(progressInterval);
                $progress.hide();
                $logSection.hide();
                $button.prop('disabled', false);
                $cancelButton.prop('disabled', true);
                $resetButton.prop('disabled', false);
                alert((err && err.message) ? err.message : atomicedgeAdmin.strings.error);
            });
        },

        /**
         * Cancel an in-progress scan.
         */
        cancelScan: function() {
            var $button = $('#atomicedge-run-scan');
            var $cancelButton = $('#atomicedge-cancel-scan');
            var $resetButton = $('#atomicedge-reset-scan');
            var $progress = $('#atomicedge-scan-progress');
            var $logSection = $('#atomicedge-scan-log');

            if (!confirm('Cancel the current scan?')) {
                return;
            }

            if (this.state.scan) {
                this.state.scan.cancelled = true;
                if (this.state.scan.pollTimeout) {
                    clearTimeout(this.state.scan.pollTimeout);
                }
                if (this.state.scan.progressInterval) {
                    clearInterval(this.state.scan.progressInterval);
                }
            }

            $cancelButton.prop('disabled', true);

            this.ajax('atomicedge_cancel_scan', { run_id: (this.state.scan && this.state.scan.runId) ? this.state.scan.runId : '' }, function() {
                $progress.hide();
                $logSection.hide();
                $button.prop('disabled', false);
                $resetButton.prop('disabled', false);
                location.reload();
            }, function(err) {
                $progress.hide();
                $logSection.hide();
                $button.prop('disabled', false);
                $resetButton.prop('disabled', false);
                alert((err && err.message) ? err.message : atomicedgeAdmin.strings.error);
            });
        },

        /**
         * Reset scan state/cache (transients + queue) so a new scan starts fresh.
         */
        resetScan: function() {
            var $button = $('#atomicedge-run-scan');
            var $cancelButton = $('#atomicedge-cancel-scan');
            var $resetButton = $('#atomicedge-reset-scan');

            if (!confirm('Reset the scan state? This will clear any in-progress scan and start fresh.')) {
                return;
            }

            if (this.state.scan) {
                this.state.scan.cancelled = true;
                if (this.state.scan.pollTimeout) {
                    clearTimeout(this.state.scan.pollTimeout);
                }
                if (this.state.scan.progressInterval) {
                    clearInterval(this.state.scan.progressInterval);
                }
            }

            $button.prop('disabled', true);
            $cancelButton.prop('disabled', true);
            $resetButton.prop('disabled', true);

            this.ajax('atomicedge_reset_scan', {}, function() {
                location.reload();
            }, function(err) {
                $button.prop('disabled', false);
                $cancelButton.prop('disabled', true);
                $resetButton.prop('disabled', false);
                alert((err && err.message) ? err.message : atomicedgeAdmin.strings.error);
            });
        },

        /**
         * Clear API cache
         */
        clearCache: function() {
            var $status = $('#atomicedge-cache-status');
            $status.text(atomicedgeAdmin.strings.loading);

            this.ajax('atomicedge_clear_cache', {}, function() {
                $status.text(atomicedgeAdmin.strings.success);
                setTimeout(function() {
                    $status.text('');
                }, 3000);
            }, function() {
                $status.text(atomicedgeAdmin.strings.error);
            });
        },

        /**
         * AJAX helper.
         *
         * On nonce expiry the helper transparently refreshes the nonce and
         * retries the original request once. If the retry also fails the
         * error is surfaced to the caller normally.
         *
         * @param {string}   action   WordPress AJAX action name.
         * @param {Object}   data     POST data (action & nonce are added automatically).
         * @param {Function} success  Callback on success (receives response.data).
         * @param {Function} error    Callback on failure (receives response.data).
         * @param {boolean}  _isRetry Internal flag — do not set manually.
         */
        ajax: function(action, data, success, error, _isRetry) {
            var self = this;
            data = data || {};
            data.action = action;
            data.nonce = atomicedgeAdmin.nonce;

            $.ajax({
                url: atomicedgeAdmin.ajaxUrl,
                type: 'POST',
                data: data,
                success: function(response) {
                    // Transparent nonce refresh: if the server flags a nonce
                    // error and this is not already a retry, fetch a fresh
                    // nonce and replay the request.
                    if (!response.success && response.data && response.data.nonce_error && !_isRetry) {
                        self.refreshNonceAndRetry(action, data, success, error);
                        return;
                    }

                    if (response.success) {
                        if (typeof success === 'function') {
                            success(response.data);
                        }
                    } else {
                        if (typeof error === 'function') {
                            error(response.data);
                        } else {
                            var message = (response.data && response.data.message) ? response.data.message : atomicedgeAdmin.strings.error;
                            self.showNotice(message, 'error');
                        }
                    }
                },
                error: function() {
                    if (typeof error === 'function') {
                        error();
                    } else {
                        self.showNotice(atomicedgeAdmin.strings.error, 'error');
                    }
                }
            });
        },

        /**
         * Fetch a fresh nonce from the server and replay the failed request.
         *
         * The refresh endpoint is cookie-authenticated (no nonce required)
         * so it succeeds even when the original nonce has expired.
         *
         * @param {string}   action  Original AJAX action.
         * @param {Object}   data    Original POST data.
         * @param {Function} success Original success callback.
         * @param {Function} error   Original error callback.
         */
        refreshNonceAndRetry: function(action, data, success, error) {
            var self = this;

            $.ajax({
                url: atomicedgeAdmin.ajaxUrl,
                type: 'POST',
                data: { action: 'atomicedge_refresh_nonce' },
                success: function(response) {
                    if (response.success && response.data && response.data.nonce) {
                        // Store the fresh nonce for all future requests.
                        atomicedgeAdmin.nonce = response.data.nonce;
                        // Replay the original request (flagged as retry).
                        self.ajax(action, data, success, error, true);
                    } else {
                        self.showNotice(
                            'Your session has expired. Please refresh the page and try again.',
                            'error'
                        );
                    }
                },
                error: function() {
                    self.showNotice(
                        'Your session has expired. Please refresh the page and try again.',
                        'error'
                    );
                }
            });
        },

        /**
         * Validate IP address or CIDR
         */
        validateIp: function(ip) {
            // IPv4
            var ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
            // IPv6 (simplified)
            var ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$/;
            
            return ipv4Regex.test(ip) || ipv6Regex.test(ip);
        },

        /**
         * Format number with commas
         */
        formatNumber: function(num) {
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        /**
         * Show a temporary admin notice.
         *
         * @param {string} message Notice message.
         * @param {string} type    Notice type (success, error, warning, info).
         */
        showNotice: function(message, type) {
            type = type || 'info';
            var $notice = $(
                '<div class="notice notice-' + type + ' is-dismissible atomicedge-notice">' +
                '<p>' + this.escapeHtml(message) + '</p>' +
                '<button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button>' +
                '</div>'
            );

            // Insert at top of page content.
            $('.wrap h1').first().after($notice);

            // Bind dismiss handler.
            $notice.find('.notice-dismiss').on('click', function() {
                $notice.fadeOut(200, function() { $(this).remove(); });
            });

            // Auto dismiss after 5 seconds.
            setTimeout(function() {
                $notice.fadeOut(200, function() { $(this).remove(); });
            }, 5000);
        },

        /**
         * Escape HTML
         */
        escapeHtml: function(str) {
            if (!str) return '';
            var div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        },

        /**
         * Get chart options
         */
        getChartOptions: function() {
            return {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            };
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        AtomicEdge.init();
    });

})(jQuery);
