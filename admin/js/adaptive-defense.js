/**
 * AtomicEdge Adaptive Defense JavaScript
 *
 * Handles all AJAX interactions for the Adaptive Defense admin page.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

/* global jQuery, atomicedge_admin */
(function($) {
    'use strict';

    var AtomicEdgeAD = {
        /** Current page for each section */
        pages: {
            blocked: 1,
            actors: 1,
            detections: 1
        },

        /** Items per page */
        perPage: 20,

        /**
         * Initialize the Adaptive Defense module
         */
        init: function() {
            if ($('#atomicedge-adaptive-defense-page').length === 0) {
                return;
            }

            this.bindEvents();
            this.loadCurrentTab();
        },

        /**
         * Load content for the currently visible tab (server-side rendered)
         */
        loadCurrentTab: function() {
            // Detect which tab is visible by checking for tab-specific elements
            if ($('#atomicedge-ad-status-card').length) {
                this.loadStatusTab();
            } else if ($('#atomicedge-ad-blocked-card').length) {
                this.loadBlockedIps();
            } else if ($('#atomicedge-ad-actors-card').length) {
                this.loadActorProfiles();
            } else if ($('#atomicedge-ad-detections-card').length) {
                this.loadThreatDetections();
            }
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            var self = this;

            // Tab navigation is handled server-side, no need to intercept clicks
            // Just bind refresh buttons and other interactive elements

            // Status tab refresh
            $('#atomicedge-ad-status-refresh').on('click', function() {
                self.loadStatusTab();
            });

            // Blocked IPs tab
            $('#atomicedge-ad-blocked-refresh').on('click', function() {
                self.loadBlockedIps();
            });
            // Block IP button click (not form submit)
            $('#atomicedge-ad-block-btn').on('click', function(e) {
                e.preventDefault();
                self.blockIpFromForm();
            });
            $(document).on('click', '.atomicedge-ad-unblock-btn', function() {
                var ip = $(this).data('ip');
                self.unblockIp(ip);
            });

            // Actor Profiles tab
            $('#atomicedge-ad-actors-refresh').on('click', function() {
                self.loadActorProfiles();
            });
            $('#atomicedge-ad-actors-filter').on('change', function() {
                self.pages.actors = 1;
                self.loadActorProfiles();
            });
            $('#atomicedge-ad-actors-search').on('keypress', function(e) {
                if (e.which === 13) {
                    self.pages.actors = 1;
                    self.loadActorProfiles();
                }
            });
            // Search button click handler
            $('#atomicedge-ad-actors-search-btn').on('click', function() {
                self.pages.actors = 1;
                self.loadActorProfiles();
            });
            $(document).on('click', '.atomicedge-ad-block-actor-btn', function() {
                var ip = $(this).data('ip');
                self.blockIp(ip, 'actor');
            });
            $(document).on('click', '.atomicedge-ad-delete-actor-btn', function() {
                var id = $(this).data('id');
                var ip = $(this).data('ip');
                self.deleteActor(id, ip);
            });

            // Threat Detections tab
            $('#atomicedge-ad-detections-refresh').on('click', function() {
                self.loadThreatDetections();
            });
            $('#atomicedge-ad-detections-status').on('change', function() {
                self.pages.detections = 1;
                self.loadThreatDetections();
            });
            $(document).on('click', '.atomicedge-ad-view-detection-btn', function() {
                var id = $(this).data('id');
                var $row = $(this).closest('tr');
                self.toggleDetectionDetail(id, $row);
            });
            $(document).on('click', '.atomicedge-ad-block-detection-btn', function() {
                var ip = $(this).data('ip');
                self.blockIp(ip, 'detection');
            });
            $(document).on('click', '.atomicedge-ad-dismiss-btn', function() {
                var id = $(this).data('id');
                self.dismissDetection(id);
            });
            $(document).on('click', '.atomicedge-ad-detail-close', function() {
                $(this).closest('.atomicedge-ad-detail-row').remove();
            });

            // Pagination
            $(document).on('click', '.atomicedge-ad-page-btn', function() {
                var section = $(this).data('section');
                var page = $(this).data('page');
                self.pages[section] = page;
                
                switch (section) {
                    case 'blocked':
                        self.loadBlockedIps();
                        break;
                    case 'actors':
                        self.loadActorProfiles();
                        break;
                    case 'detections':
                        self.loadThreatDetections();
                        break;
                }
            });
        },

        /**
         * Switch to a tab
         *
         * @param {string} tab Tab identifier
         */
        switchTab: function(tab) {
            // Update nav tabs
            $('.nav-tab').removeClass('nav-tab-active');
            $('.nav-tab[data-tab="' + tab + '"]').addClass('nav-tab-active');

            // Update tab panels
            $('.atomicedge-ad-tab-panel').removeClass('active');
            $('#atomicedge-ad-tab-' + tab).addClass('active');

            // Load tab content
            switch (tab) {
                case 'status':
                    this.loadStatusTab();
                    break;
                case 'blocked':
                    this.loadBlockedIps();
                    break;
                case 'actors':
                    this.loadActorProfiles();
                    break;
                case 'detections':
                    this.loadThreatDetections();
                    break;
            }
        },

        /**
         * Load Status tab content
         */
        loadStatusTab: function() {
            var self = this;
            var $loading = $('#atomicedge-ad-status-loading');
            var $content = $('#atomicedge-ad-status-content');

            $loading.show();
            $content.hide();

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_get_adaptive_defense',
                    nonce: atomicedge_admin.nonce
                },
                success: function(response) {
                    $loading.hide();

                    if (response.success && response.data) {
                        self.renderStatusTab(response.data);
                        $content.show();
                    } else {
                        self.showError($content, response.data ? response.data.message : 'Failed to load status');
                        $content.show();
                    }
                },
                error: function(xhr, status, error) {
                    $loading.hide();
                    self.showError($content, 'Network error: ' + error);
                    $content.show();
                }
            });
        },

        /**
         * Render Status tab content
         *
         * @param {Object} data API response data
         */
        renderStatusTab: function(data) {
            // Update status badge
            var $status = $('#atomicedge-ad-status-badge');
            var enabled = data.settings && data.settings.enabled;
            $status.removeClass('atomicedge-ad-badge-enabled atomicedge-ad-badge-disabled');
            
            if (enabled) {
                $status.addClass('atomicedge-ad-badge-enabled').text('Enabled');
            } else {
                $status.addClass('atomicedge-ad-badge-disabled').text('Disabled');
            }

            // Update threat level
            var threatLevel = data.threat_level || 'low';
            var $threatLevel = $('#atomicedge-ad-threat-level');
            $threatLevel.html(this.formatThreatLevel(threatLevel));

            // Update stats - IDs must match those in adaptive-defense-status-tab.php
            var stats = data.stats || {};
            $('#atomicedge-ad-stat-actors').text(stats.total_actors || 0);
            $('#atomicedge-ad-stat-blocked').text(stats.blocked_ips || stats.blocked_count || 0);
            $('#atomicedge-ad-stat-pending').text(stats.pending_detections || stats.pending_reviews || 0);
            $('#atomicedge-ad-stat-high-risk').text(stats.high_threat_count || 0);
            
            // Update AI budget in settings section
            $('#atomicedge-ad-budget-used').text(stats.budget_used || stats.ai_budget_used || 0);
            $('#atomicedge-ad-budget-total').text(stats.ai_budget_total || 0);

            // Update settings display
            var settings = data.settings || {};
            $('#atomicedge-ad-mode').text(this.formatMode(settings.mode || 'monitor'));
            $('#atomicedge-ad-sensitivity').text(this.formatSensitivity(settings.sensitivity || 'balanced'));

            // High-risk actors preview
            this.renderHighRiskActors(data.high_risk_actors || []);
        },

        /**
         * Render high-risk actors preview
         *
         * @param {Array} actors High-risk actors list
         */
        renderHighRiskActors: function(actors) {
            var $section = $('#atomicedge-ad-high-risk-section');
            var $tbody = $('#atomicedge-ad-high-risk-body');
            var $table = $('#atomicedge-ad-high-risk-table');

            $tbody.empty();

            if (!actors || actors.length === 0) {
                $section.hide();
                return;
            }

            // Show section and table when we have high-risk actors
            $section.show();
            $table.show();

            var self = this;
            actors.slice(0, 5).forEach(function(actor) {
                var ipAddress = actor.ip_address || actor.ip || '';
                var html = '<tr>';
                html += '<td>' + self.escapeHtml(ipAddress) + '</td>';
                html += '<td>' + self.formatScore(actor.threat_score || actor.score || 0) + '</td>';
                html += '<td>' + (actor.requests || actor.total_requests || 0) + '</td>';
                html += '<td>' + (actor.waf_hits || actor.total_waf_hits || 0) + '</td>';
                html += '<td>';
                html += '<button type="button" class="button button-small atomicedge-ad-block-actor-btn" data-ip="' + self.escapeHtml(ipAddress) + '" title="Block IP">';
                html += '<span class="dashicons dashicons-shield" style="margin-top: 3px;"></span></button>';
                html += '</td>';
                html += '</tr>';
                $tbody.append(html);
            });
        },

        /**
         * Load Blocked IPs
         */
        loadBlockedIps: function() {
            var self = this;
            var $loading = $('#atomicedge-ad-blocked-loading');
            var $wrapper = $('#atomicedge-ad-blocked-table-wrapper');

            $loading.show();
            $wrapper.hide();

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_get_adaptive_defense',
                    nonce: atomicedge_admin.nonce
                },
                success: function(response) {
                    $loading.hide();
                    $wrapper.show();

                    if (response.success && response.data && response.data.blocked_ips) {
                        self.renderBlockedIps(response.data.blocked_ips);
                    } else {
                        self.renderBlockedIps([]);
                    }
                },
                error: function(xhr, status, error) {
                    $loading.hide();
                    $wrapper.show();
                    self.showTableError('#atomicedge-ad-blocked-body', 'Network error: ' + error);
                }
            });
        },

        /**
         * Render Blocked IPs table
         *
         * @param {Array} blockedIps List of blocked IPs
         */
        renderBlockedIps: function(blockedIps) {
            var $tbody = $('#atomicedge-ad-blocked-body');
            var $empty = $('#atomicedge-ad-blocked-empty');
            var $table = $('#atomicedge-ad-blocked-table');

            $tbody.empty();

            if (!blockedIps || blockedIps.length === 0) {
                $table.hide();
                $empty.show();
                return;
            }

            $table.show();
            $empty.hide();

            var self = this;
            blockedIps.forEach(function(blocked) {
                var ipAddress = blocked.ip_address || blocked.ip || '';
                var html = '<tr>';
                html += '<td>' + self.escapeHtml(ipAddress) + '</td>';
                html += '<td>' + self.formatScore(blocked.score || 0) + '</td>';
                html += '<td>' + (blocked.waf_hits || 0) + '</td>';
                // Expires column
                if (blocked.is_permanent) {
                    html += '<td>Never (Permanent)</td>';
                } else if (blocked.expires) {
                    html += '<td>' + self.formatDate(blocked.expires) + '</td>';
                } else {
                    html += '<td>&mdash;</td>';
                }
                html += '<td>';
                html += '<button type="button" class="button button-small atomicedge-ad-unblock-btn" data-ip="' + self.escapeHtml(ipAddress) + '">';
                html += '<span class="dashicons dashicons-unlock" style="margin-top: 3px;"></span> Unblock</button>';
                html += '</td>';
                html += '</tr>';
                $tbody.append(html);
            });
        },

        /**
         * Block an IP address from the form
         */
        blockIpFromForm: function() {
            var self = this;
            var ip = $('#atomicedge-ad-block-ip').val().trim();
            var durationValue = $('#atomicedge-ad-block-duration').val();
            
            if (!ip) {
                alert('Please enter an IP address');
                return;
            }

            var permanent = durationValue === 'permanent';
            var durationHours = permanent ? 24 : parseInt(durationValue, 10);

            var $btn = $('#atomicedge-ad-block-btn');
            $btn.prop('disabled', true).text('Blocking...');

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_block_ip',
                    nonce: atomicedge_admin.nonce,
                    ip: ip,
                    duration_hours: durationHours,
                    permanent: permanent ? 'true' : 'false'
                },
                success: function(response) {
                    $btn.prop('disabled', false).html('<span class="dashicons dashicons-lock" style="margin-top: 3px;"></span> Block IP');
                    
                    if (response.success) {
                        $('#atomicedge-ad-block-ip').val('');
                        self.showNotice('IP address blocked successfully', 'success');
                        self.loadBlockedIps();
                    } else {
                        self.showNotice(response.data ? response.data.message : 'Failed to block IP', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    $btn.prop('disabled', false).html('<span class="dashicons dashicons-lock" style="margin-top: 3px;"></span> Block IP');
                    self.showNotice('Network error: ' + error, 'error');
                }
            });
        },

        /**
         * Block an IP address
         *
         * @param {string} ip Optional IP address (from form if not provided)
         * @param {string} source Source context (form, actor, detection)
         */
        blockIp: function(ip, source) {
            var self = this;
            source = source || 'form';
            
            if (!ip && source === 'form') {
                ip = $('#atomicedge-ad-block-ip').val().trim();
            }

            if (!ip) {
                alert('Please enter an IP address');
                return;
            }

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_block_ip',
                    nonce: atomicedge_admin.nonce,
                    ip: ip,
                    duration_hours: 24,
                    permanent: 'false'
                },
                beforeSend: function() {
                    if (source === 'form') {
                        $('#atomicedge-ad-block-ip-submit').prop('disabled', true).text('Blocking...');
                    }
                },
                success: function(response) {
                    if (source === 'form') {
                        $('#atomicedge-ad-block-ip-submit').prop('disabled', false).text('Block IP');
                    }

                    if (response.success) {
                        if (source === 'form') {
                            $('#atomicedge-ad-block-ip').val('');
                            $('#atomicedge-ad-block-reason').val('');
                        }
                        self.showNotice('IP address blocked successfully', 'success');
                        self.loadBlockedIps();
                        
                        // Refresh other tabs if needed
                        if (source === 'actor') {
                            self.loadActorProfiles();
                        } else if (source === 'detection') {
                            self.loadThreatDetections();
                        }
                    } else {
                        self.showNotice(response.data ? response.data.message : 'Failed to block IP', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    if (source === 'form') {
                        $('#atomicedge-ad-block-ip-submit').prop('disabled', false).text('Block IP');
                    }
                    self.showNotice('Network error: ' + error, 'error');
                }
            });
        },

        /**
         * Unblock an IP address
         *
         * @param {string} ip IP address to unblock
         */
        unblockIp: function(ip) {
            var self = this;

            if (!confirm('Are you sure you want to unblock ' + ip + '?')) {
                return;
            }

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_unblock_ip',
                    nonce: atomicedge_admin.nonce,
                    ip: ip
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('IP address unblocked successfully', 'success');
                        self.loadBlockedIps();
                    } else {
                        self.showNotice(response.data ? response.data.message : 'Failed to unblock IP', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    self.showNotice('Network error: ' + error, 'error');
                }
            });
        },

        /**
         * Load Actor Profiles
         */
        loadActorProfiles: function() {
            var self = this;
            var $loading = $('#atomicedge-ad-actors-loading');
            var $wrapper = $('#atomicedge-ad-actors-table-wrapper');
            var filter = $('#atomicedge-ad-actors-filter').val();
            var search = $('#atomicedge-ad-actors-search').val().trim();

            $loading.show();
            $wrapper.hide();

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_get_actor_profiles',
                    nonce: atomicedge_admin.nonce,
                    filter: filter,
                    search: search,
                    page: self.pages.actors,
                    per_page: self.perPage
                },
                success: function(response) {
                    $loading.hide();
                    $wrapper.show();

                    if (response.success && response.data) {
                        self.renderActorProfiles(response.data.actors || response.data);
                        self.renderPagination('actors', response.data.pagination);
                    } else {
                        self.renderActorProfiles([]);
                    }
                },
                error: function(xhr, status, error) {
                    $loading.hide();
                    $wrapper.show();
                    self.showTableError('#atomicedge-ad-actors-body', 'Network error: ' + error);
                }
            });
        },

        /**
         * Render Actor Profiles table
         *
         * @param {Array} actors List of actor profiles
         */
        renderActorProfiles: function(actors) {
            var $tbody = $('#atomicedge-ad-actors-body');
            var $empty = $('#atomicedge-ad-actors-empty');
            var $table = $('#atomicedge-ad-actors-table');

            $tbody.empty();

            if (!actors || actors.length === 0) {
                $table.hide();
                $empty.show();
                return;
            }

            $table.show();
            $empty.hide();

            var self = this;
            actors.forEach(function(actor) {
                var score = actor.score || actor.threat_score || 0;
                var ipAddress = actor.ip_address || actor.ip || '';
                var html = '<tr>';
                html += '<td>' + self.escapeHtml(ipAddress) + '</td>';
                html += '<td>' + self.formatScore(score) + '</td>';
                html += '<td>' + (actor.total_requests || actor.requests || 0) + '</td>';
                html += '<td>' + (actor.waf_hits || 0) + '</td>';
                html += '<td>' + (actor.error_4xx || 0) + '/' + (actor.error_5xx || 0) + '</td>';
                // Status column
                html += '<td>';
                if (actor.is_blocked) {
                    html += '<span class="atomicedge-ad-status-blocked">Blocked</span>';
                } else if (score >= 70) {
                    html += '<span class="atomicedge-ad-status-high-risk">High Risk</span>';
                } else {
                    html += '<span class="atomicedge-ad-status-normal">&mdash;</span>';
                }
                html += '</td>';
                html += '<td>' + self.formatDate(actor.last_seen_at || actor.last_seen || actor.updated_at) + '</td>';
                html += '<td>';
                if (!actor.is_blocked) {
                    html += '<button type="button" class="button button-small atomicedge-ad-block-actor-btn" data-ip="' + self.escapeHtml(ipAddress) + '" title="Block this IP">';
                    html += '<span class="dashicons dashicons-shield" style="margin-top: 3px;"></span></button> ';
                }
                html += '<button type="button" class="button button-small atomicedge-ad-delete-actor-btn" data-id="' + actor.id + '" data-ip="' + self.escapeHtml(ipAddress) + '" title="Delete actor profile">';
                html += '<span class="dashicons dashicons-trash" style="margin-top: 3px;"></span></button>';
                html += '</td>';
                html += '</tr>';
                $tbody.append(html);
            });
        },

        /**
         * Delete an actor profile
         *
         * @param {number} id Actor ID
         * @param {string} ip Actor IP address
         */
        deleteActor: function(id, ip) {
            var self = this;

            if (!confirm('Are you sure you want to delete the actor profile for ' + ip + '? This will also delete associated threat detections.')) {
                return;
            }

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_delete_actor',
                    nonce: atomicedge_admin.nonce,
                    actor_id: id
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('Actor profile deleted successfully', 'success');
                        self.loadActorProfiles();
                    } else {
                        self.showNotice(response.data ? response.data.message : 'Failed to delete actor profile', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    self.showNotice('Network error: ' + error, 'error');
                }
            });
        },

        /**
         * Load Threat Detections
         */
        loadThreatDetections: function() {
            var self = this;
            var $loading = $('#atomicedge-ad-detections-loading');
            var $wrapper = $('#atomicedge-ad-detections-table-wrapper');
            var status = $('#atomicedge-ad-detections-status').val();

            $loading.show();
            $wrapper.hide();

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_get_threat_detections',
                    nonce: atomicedge_admin.nonce,
                    status: status !== 'all' ? status : '',
                    page: self.pages.detections,
                    per_page: self.perPage
                },
                success: function(response) {
                    $loading.hide();
                    $wrapper.show();

                    if (response.success && response.data) {
                        self.renderThreatDetections(response.data.detections || response.data);
                        self.renderPagination('detections', response.data.pagination);
                    } else {
                        self.renderThreatDetections([]);
                    }
                },
                error: function(xhr, status, error) {
                    $loading.hide();
                    $wrapper.show();
                    self.showTableError('#atomicedge-ad-detections-body', 'Network error: ' + error);
                }
            });
        },

        /**
         * Render Threat Detections table
         *
         * @param {Array} detections List of threat detections
         */
        renderThreatDetections: function(detections) {
            var $tbody = $('#atomicedge-ad-detections-body');
            var $empty = $('#atomicedge-ad-detections-empty');
            var $table = $('#atomicedge-ad-detections-table');

            $tbody.empty();

            if (!detections || detections.length === 0) {
                $table.hide();
                $empty.show();
                return;
            }

            $table.show();
            $empty.hide();

            var self = this;
            detections.forEach(function(detection) {
                var ipAddress = detection.ip_address || detection.ip || (detection.actor && detection.actor.ip_address) || 'N/A';
                var html = '<tr data-detection-id="' + detection.id + '">';
                html += '<td>' + self.escapeHtml(ipAddress) + '</td>';
                html += '<td>' + self.formatScore(detection.score || 0) + '</td>';
                html += '<td>' + self.formatThreatLevel(detection.threat_level || 'low') + '</td>';
                html += '<td>' + self.formatIndicators(detection.reasons || detection.reasons_summary || detection.key_indicators || []) + '</td>';
                html += '<td>' + self.formatDetectionStatus(detection.status || 'pending') + '</td>';
                html += '<td>' + self.formatDate(detection.created_at || detection.detected_at) + '</td>';
                html += '<td>';
                html += '<button type="button" class="button button-small atomicedge-ad-view-detection-btn" data-id="' + detection.id + '" title="View details">';
                html += '<span class="dashicons dashicons-visibility" style="margin-top: 3px;"></span></button> ';
                if (detection.status !== 'blocked') {
                    html += '<button type="button" class="button button-small atomicedge-ad-block-detection-btn" data-ip="' + self.escapeHtml(ipAddress) + '" title="Block IP">';
                    html += '<span class="dashicons dashicons-shield" style="margin-top: 3px;"></span></button> ';
                }
                if (detection.status === 'pending' || detection.status === 'pending_review') {
                    html += '<button type="button" class="button button-small atomicedge-ad-dismiss-btn" data-id="' + detection.id + '" title="Dismiss">';
                    html += '<span class="dashicons dashicons-dismiss" style="margin-top: 3px;"></span></button>';
                }
                html += '</td>';
                html += '</tr>';
                $tbody.append(html);
            });
        },

        /**
         * Toggle detection detail view (inline expandable row)
         *
         * @param {number} id Detection ID
         * @param {jQuery} $row Table row element
         */
        toggleDetectionDetail: function(id, $row) {
            var self = this;
            var $existingDetail = $row.next('.atomicedge-ad-detail-row');

            // If detail row already exists, toggle it
            if ($existingDetail.length) {
                $existingDetail.remove();
                return;
            }

            // Remove any other open detail rows
            $('.atomicedge-ad-detail-row').remove();

            // Clone the detail template and insert it
            var $template = $('#atomicedge-ad-detection-detail-template').find('tr').clone();
            $row.after($template);

            // Load detail data
            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_get_threat_detection_detail',
                    nonce: atomicedge_admin.nonce,
                    detection_id: id
                },
                success: function(response) {
                    var $detailRow = $row.next('.atomicedge-ad-detail-row');
                    $detailRow.find('.atomicedge-ad-detail-loading').hide();
                    
                    if (response.success && response.data) {
                        self.renderDetectionDetail($detailRow, response.data);
                        $detailRow.find('.atomicedge-ad-detail-content').show();
                    } else {
                        $detailRow.find('.atomicedge-ad-detail-content').html(
                            '<p style="color: #d63638;">Failed to load detection details.</p>'
                        ).show();
                    }
                },
                error: function(xhr, status, error) {
                    var $detailRow = $row.next('.atomicedge-ad-detail-row');
                    $detailRow.find('.atomicedge-ad-detail-loading').hide();
                    $detailRow.find('.atomicedge-ad-detail-content').html(
                        '<p style="color: #d63638;">Network error: ' + self.escapeHtml(error) + '</p>'
                    ).show();
                }
            });
        },

        /**
         * Render detection detail in the expanded row
         *
         * @param {jQuery} $detailRow The detail row element
         * @param {Object} data Detection detail data
         */
        renderDetectionDetail: function($detailRow, data) {
            var detection = data.detection || data;
            var actor = detection.actor || data.actor || {};

            // Detection details
            $detailRow.find('.atomicedge-ad-detail-score').html(this.formatScore(detection.score || 0));
            $detailRow.find('.atomicedge-ad-detail-confidence').text((detection.confidence || 0) + '%');
            $detailRow.find('.atomicedge-ad-detail-status').html(this.formatDetectionStatus(detection.status || 'pending'));
            $detailRow.find('.atomicedge-ad-detail-detected-at').text(this.formatDate(detection.created_at));

            // Actor details
            $detailRow.find('.atomicedge-ad-detail-ip').text(actor.ip_address || detection.ip_address || 'N/A');
            $detailRow.find('.atomicedge-ad-detail-requests').text(actor.total_requests || 0);
            $detailRow.find('.atomicedge-ad-detail-waf-hits').text(actor.waf_hits || 0);
            $detailRow.find('.atomicedge-ad-detail-errors').text((actor.error_4xx || 0) + ' / ' + (actor.error_5xx || 0));
            $detailRow.find('.atomicedge-ad-detail-first-seen').text(this.formatDate(actor.first_seen_at));
            $detailRow.find('.atomicedge-ad-detail-last-seen').text(this.formatDate(actor.last_seen_at || actor.updated_at));

            // Reasons
            var $reasons = $detailRow.find('.atomicedge-ad-detail-reasons');
            $reasons.empty();

            var reasons = detection.reasons || detection.key_indicators || [];
            if (reasons.length > 0) {
                var self = this;
                reasons.forEach(function(reason) {
                    if (typeof reason === 'string') {
                        $reasons.append('<li>' + self.escapeHtml(reason) + '</li>');
                    } else if (reason.indicator && reason.value) {
                        $reasons.append('<li><strong>' + self.escapeHtml(reason.indicator) + ':</strong> ' + self.escapeHtml(reason.value) + '</li>');
                    }
                });
            } else {
                $reasons.append('<li>No specific indicators recorded</li>');
            }

            // AI Analysis
            var $aiSection = $detailRow.find('.atomicedge-ad-detail-ai-section');
            if (detection.ai_analysis || detection.ai_response) {
                $aiSection.find('.atomicedge-ad-detail-ai-content').text(detection.ai_analysis || detection.ai_response);
                $aiSection.show();
            } else {
                $aiSection.hide();
            }
        },

        /**
         * Dismiss a threat detection
         *
         * @param {number} id Detection ID
         */
        dismissDetection: function(id) {
            var self = this;

            if (!confirm('Are you sure you want to dismiss this detection?')) {
                return;
            }

            $.ajax({
                url: atomicedge_admin.ajax_url,
                type: 'POST',
                data: {
                    action: 'atomicedge_dismiss_detection',
                    nonce: atomicedge_admin.nonce,
                    detection_id: id
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('Detection dismissed successfully', 'success');
                        self.loadThreatDetections();
                    } else {
                        self.showNotice(response.data ? response.data.message : 'Failed to dismiss detection', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    self.showNotice('Network error: ' + error, 'error');
                }
            });
        },

        /**
         * Render pagination controls
         *
         * @param {string} section Section identifier
         * @param {Object} pagination Pagination data
         */
        renderPagination: function(section, pagination) {
            var $container = $('#atomicedge-ad-' + section + '-pagination');
            $container.empty();

            if (!pagination || pagination.last_page <= 1) {
                return;
            }

            var html = '<div class="tablenav-pages">';
            html += '<span class="displaying-num">' + pagination.total + ' items</span>';
            html += '<span class="pagination-links">';

            // Previous
            if (pagination.current_page > 1) {
                html += '<button class="button atomicedge-ad-page-btn" data-section="' + section + '" data-page="' + (pagination.current_page - 1) + '">&laquo; Previous</button> ';
            }

            // Page indicator
            html += '<span class="paging-input">' + pagination.current_page + ' of ' + pagination.last_page + '</span>';

            // Next
            if (pagination.current_page < pagination.last_page) {
                html += ' <button class="button atomicedge-ad-page-btn" data-section="' + section + '" data-page="' + (pagination.current_page + 1) + '">Next &raquo;</button>';
            }

            html += '</span></div>';
            $container.html(html);
        },

        /* ============================
         * Formatting Helpers
         * ============================ */

        /**
         * Format score as colored badge
         *
         * @param {number} score Threat score
         * @return {string} HTML string
         */
        formatScore: function(score) {
            var className = 'atomicedge-ad-score-low';
            if (score >= 80) {
                className = 'atomicedge-ad-score-critical';
            } else if (score >= 60) {
                className = 'atomicedge-ad-score-high';
            } else if (score >= 40) {
                className = 'atomicedge-ad-score-medium';
            }
            return '<span class="atomicedge-ad-score ' + className + '">' + score + '</span>';
        },

        /**
         * Format threat level badge
         *
         * @param {string} level Threat level
         * @return {string} HTML string
         */
        formatThreatLevel: function(level) {
            var labels = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'minimal': 'Minimal'
            };
            return '<span class="atomicedge-ad-threat-level atomicedge-ad-threat-' + level + '">' + 
                   (labels[level] || level) + '</span>';
        },

        /**
         * Format detection status badge
         *
         * @param {string} status Detection status
         * @return {string} HTML string
         */
        formatDetectionStatus: function(status) {
            var labels = {
                'pending': 'Pending',
                'blocked': 'Blocked',
                'dismissed': 'Dismissed'
            };
            return '<span class="atomicedge-ad-status-badge atomicedge-ad-status-' + status + '">' + 
                   (labels[status] || status) + '</span>';
        },

        /**
         * Format key indicators (truncated list)
         *
         * @param {Array} indicators List of indicators
         * @return {string} HTML string
         */
        formatIndicators: function(indicators) {
            if (!indicators || !Array.isArray(indicators) || indicators.length === 0) {
                return '<span style="color: #646970;">—</span>';
            }

            var display = [];
            var self = this;
            
            // Filter out null/undefined values first
            var validIndicators = indicators.filter(function(ind) {
                return ind !== null && ind !== undefined;
            });
            
            if (validIndicators.length === 0) {
                return '<span style="color: #646970;">—</span>';
            }
            
            validIndicators.slice(0, 2).forEach(function(ind) {
                if (typeof ind === 'string') {
                    display.push(self.escapeHtml(ind));
                } else if (ind && ind.indicator) {
                    display.push(self.escapeHtml(ind.indicator));
                } else if (ind && ind.reason) {
                    display.push(self.escapeHtml(ind.reason));
                }
            });

            var html = display.join(', ');
            if (validIndicators.length > 2) {
                html += ' <span style="color: #646970;">+' + (validIndicators.length - 2) + ' more</span>';
            }
            return html || '<span style="color: #646970;">—</span>';
        },

        /**
         * Format operating mode
         *
         * @param {string} mode Mode value
         * @return {string} Formatted mode
         */
        formatMode: function(mode) {
            var modes = {
                'monitor': 'Monitor Only',
                'auto_enforce': 'Auto Enforce'
            };
            return modes[mode] || mode;
        },

        /**
         * Format sensitivity level
         *
         * @param {string} sensitivity Sensitivity value
         * @return {string} Formatted sensitivity
         */
        formatSensitivity: function(sensitivity) {
            var levels = {
                'low': 'Low',
                'balanced': 'Balanced',
                'high': 'High',
                'aggressive': 'Aggressive'
            };
            return levels[sensitivity] || sensitivity;
        },

        /**
         * Format duration in hours
         *
         * @param {number} hours Hours
         * @return {string} Formatted duration
         */
        formatDuration: function(hours) {
            if (hours >= 24) {
                var days = Math.floor(hours / 24);
                return days + ' day' + (days > 1 ? 's' : '');
            }
            return hours + ' hour' + (hours > 1 ? 's' : '');
        },

        /**
         * Format date string
         *
         * @param {string} dateString ISO date string
         * @return {string} Formatted date
         */
        formatDate: function(dateString) {
            if (!dateString) {
                return '—';
            }
            try {
                var date = new Date(dateString);
                return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
            } catch (e) {
                return dateString;
            }
        },

        /* ============================
         * Utility Helpers
         * ============================ */

        /**
         * Escape HTML to prevent XSS
         *
         * @param {string} str String to escape
         * @return {string} Escaped string
         */
        escapeHtml: function(str) {
            if (!str) {
                return '';
            }
            var div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        },

        /**
         * Show an error message in a table body
         *
         * @param {string} selector Table body selector
         * @param {string} message Error message
         */
        showTableError: function(selector, message) {
            $(selector).html(
                '<tr><td colspan="7" style="text-align: center; color: #d63638; padding: 20px;">' +
                '<span class="dashicons dashicons-warning"></span> ' + this.escapeHtml(message) +
                '</td></tr>'
            );
        },

        /**
         * Show an error in a content area
         *
         * @param {jQuery} $container Container element
         * @param {string} message Error message
         */
        showError: function($container, message) {
            $container.html(
                '<div class="notice notice-error" style="margin: 15px 0;">' +
                '<p><span class="dashicons dashicons-warning"></span> ' + this.escapeHtml(message) + '</p>' +
                '</div>'
            );
        },

        /**
         * Show a temporary admin notice
         *
         * @param {string} message Notice message
         * @param {string} type Notice type (success, error, warning, info)
         */
        showNotice: function(message, type) {
            type = type || 'info';
            var $notice = $(
                '<div class="notice notice-' + type + ' is-dismissible atomicedge-ad-notice">' +
                '<p>' + this.escapeHtml(message) + '</p>' +
                '<button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button>' +
                '</div>'
            );

            // Insert at top of page
            $('.wrap h1').first().after($notice);

            // Bind dismiss handler
            $notice.find('.notice-dismiss').on('click', function() {
                $notice.fadeOut(200, function() { $(this).remove(); });
            });

            // Auto dismiss after 5 seconds
            setTimeout(function() {
                $notice.fadeOut(200, function() { $(this).remove(); });
            }, 5000);
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        AtomicEdgeAD.init();
    });

})(jQuery);
