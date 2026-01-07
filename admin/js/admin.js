/**
 * AtomicEdge Admin JavaScript
 *
 * @package AtomicEdge
 */

/* global atomicedgeAdmin, Chart */

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
                    .html('<p class="atomicedge-error">' + (errorData && errorData.message ? errorData.message : atomicedgeAdmin.strings.error) + '</p>');
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
                var row = '<tr>' +
                    '<td>' + self.escapeHtml(log.event_timestamp || '') + '</td>' +
                    '<td><code>' + self.escapeHtml(log.client_ip || '') + '</code></td>' +
                    '<td>' + self.escapeHtml(log.uri || '').substring(0, 50) + '</td>' +
                    '<td><code>' + self.escapeHtml(log.waf_rule_id || '') + '</code></td>' +
                    '<td>' + self.escapeHtml(log.group || '') + '</td>' +
                    '<td><button type="button" class="button button-small atomicedge-block-ip" data-ip="' + self.escapeHtml(log.client_ip || '') + '">Block IP</button></td>' +
                    '</tr>';
                $tbody.append(row);
            });

            // Bind block IP buttons
            $tbody.find('.atomicedge-block-ip').on('click', function() {
                var ip = $(this).data('ip');
                if (confirm(atomicedgeAdmin.strings.confirm)) {
                    self.addIpBlacklist(ip, 'Blocked from WAF logs');
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
                    alert(atomicedgeAdmin.strings.invalidIp);
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
                    alert(atomicedgeAdmin.strings.invalidIp);
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
         */
        loadIpRules: function() {
            var self = this;

            this.ajax('atomicedge_get_ip_rules', {}, function(data) {
                self.renderIpList('whitelist', data.whitelist || []);
                self.renderIpList('blacklist', data.blacklist || []);
            });
        },

        /**
         * Render IP list
         */
        renderIpList: function(type, ips) {
            var $tbody = $('#atomicedge-' + type + '-body');
            $tbody.empty();

            if (ips.length === 0) {
                $tbody.html('<tr><td colspan="3">No IPs in ' + type + '</td></tr>');
                return;
            }

            var self = this;
            ips.forEach(function(item) {
                var row = '<tr>' +
                    '<td><code>' + self.escapeHtml(item.ip) + '</code></td>' +
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
         * Add IP to blacklist
         */
        addIpBlacklist: function(ip, description) {
            var self = this;
            this.ajax('atomicedge_add_ip_blacklist', { ip: ip, description: description }, function() {
                $('#blacklist-ip').val('');
                $('#blacklist-description').val('');
                self.loadIpRules();
            });
        },

        /**
         * Remove IP
         */
        removeIp: function(ip, type) {
            var self = this;
            this.ajax('atomicedge_remove_ip', { ip: ip, type: type }, function() {
                self.loadIpRules();
            });
        },

        /**
         * Load geo rules
         */
        loadGeoRules: function() {
            var self = this;

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
            var self = this;
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

            // Vulnerability scanner button (on separate page)
            if ($('#atomicedge-run-vuln-scan').length > 0) {
                $('#atomicedge-run-vuln-scan').on('click', function() {
                    self.runVulnerabilityScan();
                });
            }
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
            var self = this;
            var $button = $('#atomicedge-run-vuln-scan');
            var $progress = $('#atomicedge-vuln-progress');
            var $results = $('#atomicedge-vuln-results');

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

            this.ajax('atomicedge_run_vulnerability_scan', { force_refresh: 'true' }, function(data) {
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
                
                if (data && data.need_connection) {
                    alert('Please connect your site to AtomicEdge in the Settings page first.');
                } else {
                    alert(data.message || atomicedgeAdmin.strings.error);
                }
            });
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
            var $progress = $('#atomicedge-scan-progress');
            var $results = $('#atomicedge-scan-results');

            $button.prop('disabled', true);
            $progress.show();
            $results.hide();

            // Animate progress bar
            var $progressFill = $progress.find('.atomicedge-progress-fill');
            $progressFill.css('width', '0%');
            
            var progress = 0;
            var progressInterval = setInterval(function() {
                progress = Math.min(progress + Math.random() * 10, 90);
                $progressFill.css('width', progress + '%');
            }, 500);

            this.ajax('atomicedge_run_scan', {}, function(data) {
                clearInterval(progressInterval);
                $progressFill.css('width', '100%');
                
                setTimeout(function() {
                    $progress.hide();
                    $button.prop('disabled', false);
                    // Reload page to show results
                    location.reload();
                }, 500);
            }, function() {
                clearInterval(progressInterval);
                $progress.hide();
                $button.prop('disabled', false);
                alert(atomicedgeAdmin.strings.error);
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
         * AJAX helper
         */
        ajax: function(action, data, success, error) {
            data = data || {};
            data.action = action;
            data.nonce = atomicedgeAdmin.nonce;

            $.ajax({
                url: atomicedgeAdmin.ajaxUrl,
                type: 'POST',
                data: data,
                success: function(response) {
                    if (response.success) {
                        if (typeof success === 'function') {
                            success(response.data);
                        }
                    } else {
                        if (typeof error === 'function') {
                            error(response.data);
                        } else {
                            alert(response.data.message || atomicedgeAdmin.strings.error);
                        }
                    }
                },
                error: function() {
                    if (typeof error === 'function') {
                        error();
                    } else {
                        alert(atomicedgeAdmin.strings.error);
                    }
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
