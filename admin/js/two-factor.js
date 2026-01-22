/**
 * AtomicEdge Two-Factor Authentication JavaScript
 *
 * Handles enrollment, verification, and management UI.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

/* global jQuery, atomicedge2fa, QRCode */

(function($) {
	'use strict';

	var AtomicEdge2FA = {
		/**
		 * Current enrollment data.
		 */
		enrollmentData: null,

		/**
		 * Backup codes download content.
		 */
		downloadContent: null,

		/**
		 * Initialize the 2FA module.
		 */
		init: function() {
			this.bindEvents();
		},

		/**
		 * Bind event handlers.
		 */
		bindEvents: function() {
			var self = this;

			// Enrollment flow.
			$('#atomicedge-2fa-start').on('click', function() {
				self.startEnrollment();
			});

			$('#atomicedge-2fa-verify').on('click', function() {
				self.verifyEnrollment();
			});

			$('#atomicedge-2fa-cancel').on('click', function() {
				self.cancelEnrollment();
			});

			$('#atomicedge-2fa-finish').on('click', function() {
				window.location.reload();
			});

			// Code input - auto-submit on 6 digits.
			$('#atomicedge-2fa-verify-code').on('input', function() {
				var code = $(this).val().replace(/\D/g, '');
				$(this).val(code);
				if (code.length === 6) {
					self.verifyEnrollment();
				}
			});

			// Backup codes download.
			$('#atomicedge-2fa-download-new-codes, #atomicedge-2fa-download-codes').on('click', function() {
				self.downloadBackupCodes();
			});

			// Disable 2FA.
			$('#atomicedge-2fa-disable').on('click', function() {
				if (confirm(atomicedge2fa.strings.confirm_disable)) {
					$('#atomicedge-2fa-enabled').hide();
					$('#atomicedge-2fa-disable-confirm').show();
					$('#atomicedge-2fa-password').focus();
				}
			});

			$('#atomicedge-2fa-disable-cancel').on('click', function() {
				$('#atomicedge-2fa-disable-confirm').hide();
				$('#atomicedge-2fa-enabled').show();
				$('#atomicedge-2fa-password').val('');
			});

			$('#atomicedge-2fa-disable-confirm-btn').on('click', function() {
				self.disable2FA();
			});

			// Regenerate backup codes.
			$('#atomicedge-2fa-regenerate-codes').on('click', function() {
				if (confirm(atomicedge2fa.strings.confirm_regenerate)) {
					self.regenerateCodes();
				}
			});

			$('#atomicedge-2fa-codes-done').on('click', function() {
				$('#atomicedge-2fa-codes-display').hide();
				$('#atomicedge-2fa-enabled').show();
				window.location.reload();
			});
		},

		/**
		 * Show loading state.
		 */
		showLoading: function() {
			$('#atomicedge-2fa-loading').show();
		},

		/**
		 * Hide loading state.
		 */
		hideLoading: function() {
			$('#atomicedge-2fa-loading').hide();
		},

		/**
		 * Show a step in the enrollment flow.
		 *
		 * @param {string} step Step ID (intro, setup, codes).
		 */
		showStep: function(step) {
			$('.atomicedge-2fa-step').removeClass('active');
			$('#atomicedge-2fa-step-' + step).addClass('active');
		},

		/**
		 * Start 2FA enrollment.
		 */
		startEnrollment: function() {
			var self = this;

			this.showLoading();

			$.ajax({
				url: atomicedge2fa.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_2fa_start_enrollment',
					nonce: atomicedge2fa.nonce,
					user_id: atomicedge2fa.user_id
				},
				success: function(response) {
					self.hideLoading();

					if (response.success) {
						self.enrollmentData = response.data;
						self.renderQRCode(response.data.provisioning_uri);
						$('#atomicedge-2fa-secret-display').text(
							self.formatSecret(response.data.secret)
						);
						self.showStep('setup');
						$('#atomicedge-2fa-verify-code').focus();
					} else {
						alert(response.data.message || atomicedge2fa.strings.verification_failed);
					}
				},
				error: function() {
					self.hideLoading();
					alert(atomicedge2fa.strings.verification_failed);
				}
			});
		},

		/**
		 * Verify enrollment code.
		 */
		verifyEnrollment: function() {
			var self = this;
			var code = $('#atomicedge-2fa-verify-code').val().trim();

			if (code.length !== 6) {
				$('#atomicedge-2fa-verify-error').text('Please enter a 6-digit code.').show();
				return;
			}

			$('#atomicedge-2fa-verify-error').hide();
			this.showLoading();

			$.ajax({
				url: atomicedge2fa.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_2fa_verify_enrollment',
					nonce: atomicedge2fa.nonce,
					user_id: atomicedge2fa.user_id,
					code: code
				},
				success: function(response) {
					self.hideLoading();

					if (response.success) {
						self.downloadContent = response.data.download_content;
						self.renderBackupCodes(response.data.backup_codes, '#atomicedge-2fa-new-codes');
						self.showStep('codes');
					} else {
						$('#atomicedge-2fa-verify-error').text(response.data.message).show();
						$('#atomicedge-2fa-verify-code').val('').focus();
					}
				},
				error: function() {
					self.hideLoading();
					$('#atomicedge-2fa-verify-error').text(atomicedge2fa.strings.verification_failed).show();
				}
			});
		},

		/**
		 * Cancel enrollment.
		 */
		cancelEnrollment: function() {
			var self = this;

			$.ajax({
				url: atomicedge2fa.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_2fa_cancel_enrollment',
					nonce: atomicedge2fa.nonce,
					user_id: atomicedge2fa.user_id
				},
				complete: function() {
					self.enrollmentData = null;
					$('#atomicedge-2fa-verify-code').val('');
					$('#atomicedge-2fa-verify-error').hide();
					self.showStep('intro');
				}
			});
		},

		/**
		 * Disable 2FA.
		 */
		disable2FA: function() {
			var self = this;
			var password = $('#atomicedge-2fa-password').val();

			if (!password) {
				alert('Please enter your password.');
				return;
			}

			this.showLoading();

			$.ajax({
				url: atomicedge2fa.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_2fa_disable',
					nonce: atomicedge2fa.nonce,
					user_id: atomicedge2fa.user_id,
					password: password
				},
				success: function(response) {
					self.hideLoading();

					if (response.success) {
						window.location.reload();
					} else {
						alert(response.data.message);
						$('#atomicedge-2fa-password').val('').focus();
					}
				},
				error: function() {
					self.hideLoading();
					alert(atomicedge2fa.strings.verification_failed);
				}
			});
		},

		/**
		 * Regenerate backup codes.
		 */
		regenerateCodes: function() {
			var self = this;

			this.showLoading();

			$.ajax({
				url: atomicedge2fa.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_2fa_regenerate_codes',
					nonce: atomicedge2fa.nonce,
					user_id: atomicedge2fa.user_id
				},
				success: function(response) {
					self.hideLoading();

					if (response.success) {
						self.downloadContent = response.data.download_content;
						self.renderBackupCodes(response.data.backup_codes, '#atomicedge-2fa-codes-list');
						$('#atomicedge-2fa-enabled').hide();
						$('#atomicedge-2fa-codes-display').show();
					} else {
						alert(response.data.message);
					}
				},
				error: function() {
					self.hideLoading();
					alert(atomicedge2fa.strings.verification_failed);
				}
			});
		},

		/**
		 * Render QR code.
		 *
		 * @param {string} uri The otpauth:// URI.
		 */
		renderQRCode: function(uri) {
			var canvas = document.getElementById('atomicedge-2fa-qrcode');
			if (!canvas) {
				return;
			}

			// Clear existing QR code.
			var ctx = canvas.getContext('2d');
			ctx.clearRect(0, 0, canvas.width, canvas.height);

			// Generate QR code using the bundled library.
			if (typeof QRCode !== 'undefined') {
				QRCode.toCanvas(canvas, uri, {
					width: 200,
					margin: 2,
					color: {
						dark: '#000000',
						light: '#ffffff'
					}
				}, function(error) {
					if (error) {
						console.error('QR Code generation error:', error);
					}
				});
			}
		},

		/**
		 * Render backup codes.
		 *
		 * @param {Array}  codes    Array of backup codes.
		 * @param {string} selector Container selector.
		 */
		renderBackupCodes: function(codes, selector) {
			var $container = $(selector);
			$container.empty();

			codes.forEach(function(code) {
				$container.append('<code>' + code + '</code>');
			});
		},

		/**
		 * Format secret for display (add spaces).
		 *
		 * @param {string} secret The raw secret.
		 * @return {string} Formatted secret.
		 */
		formatSecret: function(secret) {
			return secret.match(/.{1,4}/g).join(' ');
		},

		/**
		 * Download backup codes as a text file.
		 */
		downloadBackupCodes: function() {
			if (!this.downloadContent) {
				return;
			}

			var blob = new Blob([this.downloadContent], { type: 'text/plain' });
			var url = URL.createObjectURL(blob);
			var a = document.createElement('a');
			a.href = url;
			a.download = 'atomicedge-backup-codes.txt';
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
		}
	};

	// Initialize on document ready.
	$(document).ready(function() {
		if ($('#atomicedge-2fa').length) {
			AtomicEdge2FA.init();
		}
	});

})(jQuery);
