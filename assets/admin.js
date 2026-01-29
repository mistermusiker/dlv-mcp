(function () {
    'use strict';

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
        const textarea = document.getElementById('dlv-mcp-log-textarea');
        const displayDiv = document.getElementById('dlv-mcp-log-display');
        const wrapToggle = document.getElementById('dlv-mcp-wrap-toggle');
        const copyBtn = document.getElementById('dlv-mcp-copy-button');
        const copyStatus = document.getElementById('dlv-mcp-copy-status');
        const autoRefreshToggle = document.getElementById('dlv-mcp-auto-refresh-toggle');
        const refreshBtn = document.getElementById('dlv-mcp-refresh-btn');
        const logInfo = document.getElementById('dlv-mcp-log-info');
        const searchInput = document.getElementById('dlv-mcp-search-input');
        const highlightToggle = document.getElementById('dlv-mcp-highlight-toggle');

        let autoRefreshInterval = null;
        let rawLogContent = '';
        let isRefreshing = false;

        // Settings from PHP via wp_localize_script
        const settings = window.dlvMcpSettings || {};
        const AJAX_URL = settings.ajaxurl || window.ajaxurl || '';
        const AUTO_REFRESH_ENABLED = settings.autoRefreshEnabled || false;
        const AUTO_REFRESH_INTERVAL = (settings.autoRefreshInterval || 5) * 1000;
        const HIGHLIGHT_ENABLED = settings.highlightEnabled || false;
        const strings = settings.strings || {};

        // Verify we have the ajax URL
        if (!AJAX_URL) {
            console.error('DLV MCP: AJAX URL not available');
            return;
        }

        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, function (m) { return map[m]; });
        }

        function renderLog() {
            if (!textarea) return;

            let content = rawLogContent;
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const useHighlight = highlightToggle ? highlightToggle.checked : false;
            const hideDeprecated = document.getElementById('dlv-mcp-hide-deprecated-toggle');
            const shouldHideDeprecated = hideDeprecated ? hideDeprecated.checked : false;

            // Filter by search term
            if (searchTerm) {
                const lines = content.split('\n');
                content = lines.filter(function(line) {
                    return line.toLowerCase().includes(searchTerm);
                }).join('\n');
            }

            // Filter out deprecated warnings
            if (shouldHideDeprecated) {
                const lines = content.split('\n');
                content = lines.filter(function(line) {
                    return !line.includes('Deprecated');
                }).join('\n');
            }

            // Render with or without highlighting
            if (useHighlight && displayDiv) {
                const lines = content.split('\n');
                const highlighted = lines.map(function(line) {
                    let className = 'dlv-mcp-line';
                    if (line.includes('Fatal error') || line.includes('Parse error')) {
                        className += ' dlv-mcp-fatal';
                    } else if (line.includes('Warning')) {
                        className += ' dlv-mcp-warning';
                    } else if (line.includes('Notice')) {
                        className += ' dlv-mcp-notice';
                    } else if (line.includes('Deprecated')) {
                        className += ' dlv-mcp-deprecated';
                    } else if (line.includes('[DLV MCP]')) {
                        className += ' dlv-mcp-own';
                    } else if (line.includes('PG Security') || line.includes('Prompt Guard')) {
                        className += ' dlv-mcp-pg';
                    }
                    return '<div class="' + className + '">' + escapeHtml(line) + '</div>';
                }).join('');

                displayDiv.innerHTML = highlighted;
                displayDiv.style.display = 'block';
                textarea.style.display = 'none';
                displayDiv.scrollTop = displayDiv.scrollHeight;
            } else {
                if (displayDiv) {
                    displayDiv.style.display = 'none';
                }
                textarea.style.display = 'block';
                textarea.value = content;
                textarea.scrollTop = textarea.scrollHeight;
            }
        }

        function updateLogInfo(info) {
            if (!logInfo || !info) return;

            let html = (strings.size || 'Size:') + ' ' + (info.size_human || '0 B');
            if (info.lines > 0) {
                html += ' | ' + (strings.lines || 'Lines:') + ' ' + info.lines;
            }
            logInfo.innerHTML = html;
        }

        function setRefreshButtonState(loading) {
            if (!refreshBtn) return;

            if (loading) {
                refreshBtn.disabled = true;
                refreshBtn.textContent = strings.refreshing || 'Refreshing...';
            } else {
                refreshBtn.disabled = false;
                refreshBtn.textContent = 'Refresh';
            }
        }

        function showError(message) {
            if (logInfo) {
                const originalContent = logInfo.innerHTML;
                logInfo.innerHTML = '<span style="color: #d63638;">' + escapeHtml(message) + '</span>';
                setTimeout(function() {
                    logInfo.innerHTML = originalContent;
                }, 3000);
            }
        }

        function updateLogContent(isManualRefresh) {
            if (isRefreshing) return;

            isRefreshing = true;

            if (isManualRefresh) {
                setRefreshButtonState(true);
            }

            const formData = new FormData();
            formData.append('action', 'dlv_mcp_refresh_log');
            formData.append('nonce', settings.nonce);

            fetch(AJAX_URL, {
                method: 'POST',
                body: formData,
                credentials: 'same-origin'
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(function(data) {
                isRefreshing = false;
                setRefreshButtonState(false);

                if (data.success && data.data) {
                    rawLogContent = data.data.content || '';
                    renderLog();

                    if (data.data.info) {
                        updateLogInfo(data.data.info);
                    }
                } else {
                    const errorMsg = (data.data && data.data.message)
                        ? data.data.message
                        : (strings.refreshError || 'Could not load log file.');
                    showError(errorMsg);
                }
            })
            .catch(function(error) {
                isRefreshing = false;
                setRefreshButtonState(false);
                console.error('DLV MCP: Refresh failed', error);
                showError(strings.refreshFailed || 'Refresh failed. Retrying...');
            });
        }

        function startAutoRefresh() {
            stopAutoRefresh();
            if (autoRefreshToggle && autoRefreshToggle.checked) {
                autoRefreshInterval = setInterval(function() {
                    updateLogContent(false);
                }, AUTO_REFRESH_INTERVAL);
            }
        }

        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        }

        // Event Listeners
        if (searchInput) {
            searchInput.addEventListener('input', renderLog);
        }

        if (highlightToggle) {
            // Set initial state from settings
            if (HIGHLIGHT_ENABLED) {
                highlightToggle.checked = true;
            }

            highlightToggle.addEventListener('change', function() {
                renderLog();
                saveSettingAjax('highlight', highlightToggle.checked);
            });
        }

        if (wrapToggle) {
            // Apply initial wrap state
            if (wrapToggle.checked) {
                if (textarea) textarea.classList.add('dlv-mcp-wrap-lines');
                if (displayDiv) displayDiv.classList.add('dlv-mcp-wrap-lines');
            }

            wrapToggle.addEventListener('change', function () {
                if (wrapToggle.checked) {
                    if (textarea) {
                        textarea.style.whiteSpace = 'pre-wrap';
                        textarea.classList.add('dlv-mcp-wrap-lines');
                    }
                    if (displayDiv) displayDiv.classList.add('dlv-mcp-wrap-lines');
                } else {
                    if (textarea) {
                        textarea.style.whiteSpace = 'pre';
                        textarea.classList.remove('dlv-mcp-wrap-lines');
                    }
                    if (displayDiv) displayDiv.classList.remove('dlv-mcp-wrap-lines');
                }
                saveSettingAjax('wrap_lines', wrapToggle.checked);
            });
        }

        if (copyBtn) {
            copyBtn.addEventListener('click', function () {
                const text = rawLogContent;

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text)
                        .then(function () {
                            if (copyStatus) {
                                copyStatus.textContent = strings.copied || 'Copied.';
                                setTimeout(function () { copyStatus.textContent = ''; }, 2000);
                            }
                        })
                        .catch(function () {
                            // Fallback for clipboard permission denied
                            fallbackCopy(text);
                        });
                } else {
                    // Fallback for older browsers
                    fallbackCopy(text);
                }
            });
        }

        function fallbackCopy(text) {
            const tempTextarea = document.createElement('textarea');
            tempTextarea.value = text;
            tempTextarea.style.position = 'fixed';
            tempTextarea.style.left = '-9999px';
            document.body.appendChild(tempTextarea);
            tempTextarea.select();
            try {
                document.execCommand('copy');
                if (copyStatus) {
                    copyStatus.textContent = strings.copied || 'Copied.';
                    setTimeout(function () { copyStatus.textContent = ''; }, 2000);
                }
            } catch (err) {
                if (copyStatus) {
                    copyStatus.textContent = strings.copyFailed || 'Copy failed.';
                    setTimeout(function () { copyStatus.textContent = ''; }, 2000);
                }
            }
            document.body.removeChild(tempTextarea);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener('click', function () {
                updateLogContent(true);
            });
        }

        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', function () {
                if (autoRefreshToggle.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
                saveSettingAjax('auto_refresh', autoRefreshToggle.checked);
            });
        }
        
        // Handle hide deprecated toggle
        const hideDeprecatedToggle = document.getElementById('dlv-mcp-hide-deprecated-toggle');
        if (hideDeprecatedToggle) {
            hideDeprecatedToggle.addEventListener('change', function () {
                // Just re-render with current content - no AJAX needed
                // rawLogContent already has full content from initial page load
                renderLog();
                saveSettingAjax('hide_deprecated', hideDeprecatedToggle.checked);
            });
        }
        
        // Save a single setting via AJAX (no page reload)
        function saveSettingAjax(settingName, settingValue) {
            const formData = new FormData();
            formData.append('action', 'dlv_mcp_save_settings');
            formData.append('nonce', settings.nonce);
            formData.append(settingName, settingValue ? 'true' : 'false');

            fetch(AJAX_URL, {
                method: 'POST',
                body: formData,
                credentials: 'same-origin'
            })
            .then(function(response) {
                return response.json();
            })
            .then(function(data) {
                if (!data.success) {
                    console.error('DLV MCP: Failed to save setting', settingName);
                }
            })
            .catch(function(error) {
                console.error('DLV MCP: Error saving setting', error);
            });
        }
        
        // Save auto-refresh interval when it changes
        const autoRefreshIntervalInput = document.getElementById('dlv-mcp-auto-refresh-interval');
        if (autoRefreshIntervalInput) {
            let intervalTimeout = null;
            autoRefreshIntervalInput.addEventListener('change', function () {
                // Debounce: save after 1 second of no changes
                clearTimeout(intervalTimeout);
                intervalTimeout = setTimeout(function() {
                    const formData = new FormData();
                    formData.append('action', 'dlv_mcp_save_settings');
                    formData.append('nonce', settings.nonce);
                    formData.append('auto_refresh_interval', autoRefreshIntervalInput.value);

                    fetch(AJAX_URL, {
                        method: 'POST',
                        body: formData,
                        credentials: 'same-origin'
                    }).catch(function(error) {
                        console.error('DLV MCP: Error saving interval', error);
                    });
                }, 1000);
            });
        }

        // Initial setup
        if (textarea) {
            rawLogContent = textarea.value || '';
            // Render initial content (important if highlight is enabled by default)
            renderLog();
        }

        // Start auto-refresh if enabled
        if (AUTO_REFRESH_ENABLED && autoRefreshToggle && autoRefreshToggle.checked) {
            startAutoRefresh();
        }
    }
})();
