/* ===================================================================
   Cybersecurity Detection — UI Logic
   =================================================================== */

const API_BASE_URL = '';

// Store scan results for recent scans access
const scanResultsCache = {};

/* ===== MODAL DIALOG FUNCTIONS ===== */
function showModal(title, message) {
    const modalHtml = `
        <div class="modal-overlay" id="modalOverlay" onclick="if(event.target.id === 'modalOverlay') closeModal()">
            <div class="modal-dialog">
                <div class="modal-header">
                    <h3>${title}</h3>
                    <button class="modal-close" onclick="closeModal()">×</button>
                </div>
                <div class="modal-body">
                    <p>${message.replace(/\n/g, '<br>')}</p>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="closeModal()">OK</button>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal if any
    const existing = document.getElementById('modalOverlay');
    if (existing) existing.remove();
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

function showConfirmModal(title, message, onConfirm) {
    const modalHtml = `
        <div class="modal-overlay" id="modalOverlay" onclick="if(event.target.id === 'modalOverlay') closeModal()">
            <div class="modal-dialog">
                <div class="modal-header">
                    <h3>${title}</h3>
                    <button class="modal-close" onclick="closeModal()">×</button>
                </div>
                <div class="modal-body">
                    <p>${message.replace(/\n/g, '<br>')}</p>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="confirmAction()">Confirm</button>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal if any
    const existing = document.getElementById('modalOverlay');
    if (existing) existing.remove();
    
    window.confirmCallback = onConfirm;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

function closeModal() {
    const modal = document.getElementById('modalOverlay');
    if (modal) modal.remove();
    window.confirmCallback = null;
}

function confirmAction() {
    if (window.confirmCallback) {
        window.confirmCallback();
    }
    closeModal();
}

/* ---------- Sidebar & Navigation ---------- */
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    const overlay = document.querySelector('.sidebar-overlay');
    if (overlay) overlay.classList.toggle('active');
}

function scrollToRecent() {
    document.getElementById('recentScans').scrollIntoView({ behavior: 'smooth' });
    // close mobile sidebar
    document.getElementById('sidebar').classList.remove('open');
    const overlay = document.querySelector('.sidebar-overlay');
    if (overlay) overlay.classList.remove('active');
}

function selectModule(module) {
    const m1 = document.getElementById('module1Section');
    const m2 = document.getElementById('module2Section');
    const nav1 = document.getElementById('nav-module1');
    const nav2 = document.getElementById('nav-module2');
    const title = document.getElementById('pageTitle');
    const subtitle = document.querySelector('.topbar-subtitle');

    if (module === 'module1') {
        m1.style.display = 'block';
        m2.style.display = 'none';
        nav1.classList.add('active');
        nav2.classList.remove('active');
        if (subtitle) subtitle.textContent = 'Module 1 — Sensitive Data Exposure Detection';
    } else {
        m1.style.display = 'none';
        m2.style.display = 'block';
        nav1.classList.remove('active');
        nav2.classList.add('active');
        if (subtitle) subtitle.textContent = 'Module 2 — Government Impersonation Detection';
    }
    // close mobile sidebar
    document.getElementById('sidebar').classList.remove('open');
    const overlay = document.querySelector('.sidebar-overlay');
    if (overlay) overlay.classList.remove('active');
}

/* ---------- Health Check ---------- */
async function checkHealth() {
    try {
        const res = await fetch('/api/health');
        const data = await res.json();
        // Health check silent - no badge
    } catch {
        // System offline - silent
    }
}

/* ===================== MODULE 1: SENSITIVE DATA ===================== */
async function startScan() {
    try {
        const dataTypes = Array.from(document.querySelectorAll('input[name="dataType"]:checked')).map(cb => cb.value);
        if (dataTypes.length === 0) { alert('Please select at least one data type'); return; }

        const fileTypes = Array.from(document.querySelectorAll('input[name="fileType"]:checked')).map(cb => cb.value);
        if (fileTypes.length === 0) { alert('Please select at least one file type'); return; }

        const domain = document.getElementById('domain').value;
        const maxResults = parseInt(document.getElementById('maxResults').value);

        const requestData = { data_types: dataTypes, file_types: fileTypes, domain, max_results: maxResults };

        document.getElementById('progressPanel').style.display = 'block';
        document.getElementById('resultsPanel').style.display = 'none';
        document.getElementById('progressText').textContent = 'Initializing scan...';
        document.getElementById('progressFill').style.width = '0%';
        startECG('ecgCanvas');

        const response = await fetch('/api/scan/sensitive-data', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });
        const result = await response.json();

        if (response.ok) {
            document.getElementById('scanId').textContent = result.scan_id;
            document.getElementById('progressText').textContent = 'Scan in progress — this may take a few minutes...';
            pollScanStatus(result.scan_id);
        } else {
            alert('Error: ' + result.detail);
            document.getElementById('progressPanel').style.display = 'none';
        }
    } catch (error) {
        console.error(error);
        alert('Error starting scan: ' + error.message);
        document.getElementById('progressPanel').style.display = 'none';
    }
}

let pollInterval;
function pollScanStatus(scanId) {
    let progress = 0;
    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/scan/${scanId}/status`);
            const data = await response.json();
            document.getElementById('scanStatus').textContent = data.status;

            if (data.status === 'in_progress') {
                progress = Math.min(progress + 10, 90);
                document.getElementById('progressFill').style.width = progress + '%';
                updateScanPhases('scanPhases', progress);
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('progressText').textContent = 'Scan completed!';
                document.getElementById('detectionsCount').textContent = data.results_count;
                stopECG('ecgCanvas');
                setTimeout(() => displayResults(data), 800);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('progressText').textContent = 'Scan finished (no results found)';
                document.getElementById('detectionsCount').textContent = data.results_count;
                stopECG('ecgCanvas');
                setTimeout(() => displayResults(data), 800);
            }
        } catch (e) { console.error('Poll error:', e); }
    }, 3000);
}

function displayResults(data) {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';

    // Cache the scan results for recent scans access
    scanResultsCache[data.scan_id] = {
        type: 'module1',
        data: data
    };

    // ✅ SET THE SCAN ID SO MAIN BUTTONS CAN FIND IT
    document.getElementById('scanId').textContent = data.scan_id;

    const detections = data.detections || [];
    const summary = document.getElementById('resultsSummary');
    summary.innerHTML = `
        <h4>Scan Summary</h4>
        <p><strong>Scan ID:</strong> ${data.scan_id}</p>
        <p><strong>Status:</strong> ${data.status}</p>
        <p><strong>Total Detections:</strong> ${data.results_count}</p>
        <p><strong>Started:</strong> ${new Date(data.start_time).toLocaleString()}</p>
        ${data.end_time ? `<p><strong>Completed:</strong> ${new Date(data.end_time).toLocaleString()}</p>` : ''}
    `;

    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';

    if (detections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No sensitive data leaks detected.</td></tr>';
    } else {
        detections.forEach((urlItem, index) => {
            const urlDetections = urlItem.detections || [];
            if (!urlDetections.length) return;
            const dataTypes = urlItem.data_types || [];
            const confidences = urlDetections.map(d => d.confidence).filter(c => c != null);
            const maxConf = confidences.length ? Math.max(...confidences) : 0;
            const confClass = maxConf >= 80 ? 'confidence-high' : 'confidence-medium';
            const first = urlDetections[0];
            let evidence = '';
            try { evidence = typeof first.evidence === 'string' ? (JSON.parse(first.evidence).context || first.evidence) : (first.evidence || ''); } catch { evidence = first.evidence || ''; }
            const leakIds = urlDetections.map(d => d.leak_id).join(',');
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><input type="checkbox" class="result-checkbox" value="${urlItem.file_url}"></td>
                <td><strong>${dataTypes.join(', ').replace(/_/g,' ').toUpperCase()}</strong></td>
                <td><a href="${urlItem.file_url}" target="_blank">${urlItem.file_url.substring(0,55)}…</a></td>
                <td class="${confClass}">${maxConf.toFixed(1)}%</td>
                <td>${evidence.substring(0,80)}…</td>
                <td><button class="btn btn-danger" onclick="deleteDetection('${leakIds}')">Delete</button></td>
            `;
            tbody.appendChild(row);
        });
    }
    loadRecentScans();
}

function exportResults() {
    const table = document.getElementById('resultsTable');
    let csv = [];
    const headers = Array.from(table.querySelectorAll('thead th')).slice(0, 4).map(th => th.textContent);
    csv.push(headers.join(','));
    table.querySelectorAll('tbody tr').forEach(row => {
        const cells = Array.from(row.querySelectorAll('td')).slice(0, 4).map(td => `"${td.textContent.replace(/"/g,'""')}"`);
        csv.push(cells.join(','));
    });
    const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `scan_results_${Date.now()}.csv`;
    a.click();
}

function resetScan() {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('progressFill').style.width = '0%';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ---------- Recent Scans ---------- */
async function loadRecentScans() {
    try {
        const res = await fetch('/api/scans/recent?limit=5');
        const data = await res.json();
        const list = document.getElementById('recentScansList');
        list.innerHTML = '';
        if (data.scans && data.scans.length > 0) {
            data.scans.forEach(scan => {
                const item = document.createElement('div');
                item.className = 'scan-item';
                const statusClass = scan.status === 'completed' ? 'completed' : scan.status === 'failed' ? 'failed' : 'in_progress';
                const scanType = scan.scan_type.replace(/_/g,' ');
                
                // Determine module type
                let actionButton = '';
                let scanModule = '';
                if (scan.status === 'completed') {
                    if (scan.scan_type.toLowerCase().includes('sensitive')) {
                        actionButton = `<button class="btn btn-warning btn-sm" onclick="reportFromHistoryVuln(${scan.scan_id})">Send Alert</button>`;
                        scanModule = 'module1';
                    } else if (scan.scan_type.toLowerCase().includes('government') || scan.scan_type.toLowerCase().includes('impersonate')) {
                        actionButton = `<button class="btn btn-danger btn-sm" onclick="reportFromHistoryAbuse(${scan.scan_id})">Send Report</button>`;
                        scanModule = 'module2';
                    }
                }
                
                item.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
                        <div style="flex:1; cursor:pointer;" onclick="viewScanDetails(${scan.scan_id})">
                            <strong>Scan #${scan.scan_id}</strong>
                            <span class="scan-item-status ${statusClass}">${scan.status}</span><br>
                            <span style="color:var(--text-secondary);font-size:.85rem">${scanType} &middot; ${scan.results_count} results</span><br>
                            <small>${new Date(scan.start_time).toLocaleString()}</small>
                        </div>
                        <div style="display:flex; gap:5px;">
                            ${actionButton}
                            <button class="btn btn-danger btn-sm" onclick="deleteScan(${scan.scan_id})">Delete</button>
                        </div>
                    </div>
                `;
                list.appendChild(item);
            });
        } else {
            list.innerHTML = '<p class="empty-state">No recent scans yet — start your first scan above.</p>';
        }
    } catch (e) { console.error('Error loading recent scans:', e); }
}

// Wrapper functions that call the history functions
function reportFromHistoryVuln(scanId) {
    console.log('🔹 reportFromHistoryVuln called with scanId:', scanId);
    sendVulnerabilityReportFromHistory(scanId);
}

function reportFromHistoryAbuse(scanId) {
    console.log('🔹 reportFromHistoryAbuse called with scanId:', scanId);
    sendAbuseReportFromHistory(scanId);
}

/* ---------- Delete Scan ---------- */
async function deleteScan(scanId) {
    if (!confirm(`🗑️ Are you sure you want to delete Scan #${scanId}? This action cannot be undone.`)) {
        return;
    }
    
    try {
        console.log('🗑️ Deleting scan:', scanId);
        const response = await fetch(`/api/scan/${scanId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            alert(`✅ Scan #${scanId} deleted successfully!`);
            loadRecentScans(); // Reload the recent scans list
        } else {
            const errData = await response.json();
            alert(`❌ Error: ${errData.detail || 'Failed to delete scan'}`);
        }
    } catch (error) {
        alert(`❌ Error: ${error.message}`);
        console.error('Delete error:', error);
    }
}

async function viewScanDetails(scanId) {
    try {
        const res = await fetch(`/api/scan/${scanId}/status`);
        const data = await res.json();
        selectModule('module1');
        displayResults(data);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (e) { console.error(e); }
}

/* ---------- Delete Detection ---------- */
async function deleteDetection(leakIds) {
    if (!confirm('Delete this detection record?')) return;
    try {
        const res = await fetch('/api/detections/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ leak_ids: leakIds.split(',').map(Number) })
        });
        if (res.ok) {
            alert('Detection deleted.');
            const id = document.getElementById('scanId').textContent;
            if (id && id !== '—') viewScanDetails(parseInt(id));
        } else {
            const err = await res.json();
            alert('Error: ' + (err.detail || 'Unknown'));
        }
    } catch (e) { alert('Error: ' + e.message); }
}

/* ---------- Checkbox Selection ---------- */
function toggleSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.result-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
}

function getSelectedUrls() {
    const checkboxes = document.querySelectorAll('.result-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

/* ---------- Send Selected Results Report ---------- */
async function sendSelectedReport() {
    const selectedUrls = getSelectedUrls();
    
    if (selectedUrls.length === 0) {
        showModal('No URLs Selected', 'Please select at least one URL to report');
        return;
    }
    
    const modal = showConfirmModal(
        `Send Report for ${selectedUrls.length} URL(s)`,
        `You are about to send a report for ${selectedUrls.length} selected URL(s) to CERT-In.\n\nThis will alert authorities about the sensitive data exposure on these specific URLs.`,
        async () => {
            try {
                const scanId = document.getElementById('scanId').textContent;
                const response = await fetch('/api/scan/send-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        scan_id: parseInt(scanId),
                        selected_urls: selectedUrls
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showModal('✅ Report Sent', `Report successfully sent to CERT-In!\n\nURLs reported: ${selectedUrls.length}`);
                } else {
                    const err = await response.json();
                    showModal('❌ Error', 'Error sending report: ' + (err.detail || 'Unknown error'));
                }
            } catch (error) {
                showModal('❌ Error', 'Error: ' + error.message);
            }
        }
    );
}

/* ---------- Send Vulnerability Report from History ---------- */
async function sendVulnerabilityReportFromHistory(scanId) {
    console.log('✅ sendVulnerabilityReportFromHistory started for scanId:', scanId);
    try {
        // Fetch scan details
        const res = await fetch(`/api/scan/${scanId}/status`);
        const data = await res.json();
        
        console.log('📊 Full scan data structure:', data);
        console.log('📊 Detections array:', data.detections);
        
        if (!data.detections || data.detections.length === 0) {
            alert('❌ No detections found in this scan.');
            return;
        }
        
        // Get all detected data types from the results - with detailed logging
        const dataTypes = new Set();
        data.detections.forEach((urlItem, idx) => {
            console.log(`  Detection[${idx}]:`, JSON.stringify(urlItem));
            const dataTypesList = urlItem.data_types || [];
            console.log(`  Data types list for Detection[${idx}]:`, dataTypesList);
            if (Array.isArray(dataTypesList)) {
                dataTypesList.forEach(dt => {
                    if (dt) dataTypes.add(String(dt).toLowerCase().trim());
                });
            }
        });
        
        console.log('🔍 Final extracted data types set:', Array.from(dataTypes));
        
        if (dataTypes.size === 0) {
            alert('❌ No data types detected in results. Check scan completed successfully.');
            return;
        }
        
        const dataTypeArray = Array.from(dataTypes);
        let message = '🚨 VULNERABILITY REPORT\n\nDetected Data Types:\n';
        dataTypeArray.forEach(dt => message += `  • ${dt.toUpperCase()}\n`);
        message += `\nSend information disclosure vulnerability reports for these data types to CERT-In?`;
        
        if (!confirm(message)) {
            return;
        }
        
        let successCount = 0;
        let failureCount = 0;
        
        for (const dataType of dataTypeArray) {
            try {
                const requestPayload = {
                    scan_id: parseInt(scanId),
                    data_type: dataType.trim()
                };
                console.log(`📤 Sending request:`, requestPayload);
                
                const response = await fetch('/api/scan/send-vulnerability-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(requestPayload)
                });
                
                console.log(`Response status for ${dataType}:`, response.status, response.statusText);
                
                if (response.ok) {
                    const result = await response.json();
                    successCount++;
                    console.log(`✅ Report sent for ${dataType}:`, result);
                } else {
                    const errData = await response.json();
                    failureCount++;
                    console.error(`❌ Failed for ${dataType}:`, errData);
                }
            } catch (error) {
                failureCount++;
                console.error(`💥 Exception for ${dataType}:`, error);
            }
        }
        
        alert(`📧 REPORTS SENT\\n\\n✅ Successful: ${successCount}\\n❌ Failed: ${failureCount}`);
        
    } catch (error) {
        alert('Error: ' + (error.message || 'Unknown error occurred'));
        console.error('💥 Top level exception:', error);
    }
}

/* ---------- Send Abuse Report from History ---------- */
async function sendAbuseReportFromHistory(scanId) {
    console.log('✅ sendAbuseReportFromHistory started for scanId:', scanId);
    try {
        // Fetch scan details from government-impersonation endpoint
        const res = await fetch(`/api/scan/${scanId}/government-impersonation`);
        const data = await res.json();
        
        if (!data.findings || data.findings.length === 0) {
            alert('❌ No impersonation threats found in this scan.');
            return;
        }
        
        // Get all detected impersonation types
        const impersonationTypes = new Set();
        data.findings.forEach(r => {
            if (r.impersonation_type) {
                impersonationTypes.add(r.impersonation_type);
            }
        });
        
        if (impersonationTypes.size === 0) {
            alert('❌ No impersonation threats detected in results. Check scan completed successfully.');
            return;
        }
        
        const typeArray = Array.from(impersonationTypes);
        let message = '⚠️ ABUSE REPORT - GOVERNMENT IMPERSONATION\n\nDetected Threat Types:\n';
        typeArray.forEach(type => message += `  • ${type.replace(/_/g, ' ').toUpperCase()}\n`);
        message += `\nSend abuse reports for detected government impersonation sites to CERT-In?`;
        
        if (!confirm(message)) {
            return;
        }
        
        let successCount = 0;
        let failureCount = 0;
        
        for (const type of typeArray) {
            try {
                const response = await fetch('/api/scan/send-abuse-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        scan_id: parseInt(scanId),
                        impersonation_type: type
                    })
                });
                
                if (response.ok) {
                    successCount++;
                    console.log(`✅ Abuse report sent for ${type}`);
                } else {
                    const errData = await response.json();
                    failureCount++;
                    console.error(`Failed for ${type}:`, errData.detail || 'Unknown error');
                }
            } catch (error) {
                failureCount++;
                console.error(`Error for ${type}:`, error.message);
            }
        }
        
        alert(`📧 REPORTS SENT\\n\\n✅ Successful: ${successCount}\\n❌ Failed: ${failureCount}`);
        
    } catch (error) {
        alert('Error: ' + (error.message || 'Unknown error occurred'));
    }
}

/* ---------- Send Vulnerability Report (Module 1) ---------- */
async function sendVulnerabilityReport() {
    try {
        const scanId = document.getElementById('scanId').textContent;
        if (!scanId || scanId === '—') {
            showModal('No Active Scan', 'No active scan found. Please complete a scan first.');
            return;
        }
        
        // Get data types from ONLY SELECTED rows
        const tbody = document.getElementById('resultsTableBody');
        const dataTypes = new Set();
        
        tbody.querySelectorAll('tr').forEach(row => {
            const checkbox = row.cells[0].querySelector('.result-checkbox');
            // Only include checked rows
            if (checkbox && checkbox.checked) {
                const dataTypeCell = row.cells[1];
                if (dataTypeCell) {
                    const dataType = dataTypeCell.textContent.trim().toLowerCase().replace(/'/g, '');
                    if (dataType && dataType !== 'no sensitive data leaks detected') {
                        dataTypes.add(dataType.split(',')[0].trim());
                    }
                }
            }
        });
        
        if (dataTypes.size === 0) {
            showModal('No Data Selected', 'Please select at least one row with data types to report.');
            return;
        }
        
        const dataTypeArray = Array.from(dataTypes);
        let message = `Detected data types in selected rows:\n\n`;
        dataTypeArray.forEach(dt => message += `  • ${dt.toUpperCase()}\n`);
        message += `\nThis will send information disclosure vulnerability reports for these data types to CERT-In.`;
        
        const modal = showConfirmModal('Send Vulnerability Report', message, async () => {
        
            let successCount = 0;
            let failureCount = 0;
            
            for (const dataType of dataTypeArray) {
                try {
                    const response = await fetch('/api/scan/send-vulnerability-report', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            scan_id: parseInt(scanId),
                            data_type: dataType.trim()
                        })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        successCount++;
                        console.log(`✅ Vulnerability report sent for ${dataType}`);
                    } else {
                        const errData = await response.json();
                        failureCount++;
                        console.error(`Failed to send report for ${dataType}:`, errData.detail || 'Unknown error');
                    }
                } catch (error) {
                    failureCount++;
                    console.error(`Error sending report for ${dataType}:`, error.message);
                }
            }
            
            showModal('Reports Sent', `✅ Successful: ${successCount}\n❌ Failed: ${failureCount}\n\nAll information disclosure vulnerability reports have been submitted to CERT-In for immediate action.`);
        });
    } catch (error) {
        showModal('Error', 'Error: ' + (error.message || 'Unknown error occurred'));
    }
}

/* ===================== MODULE 2: GIDS ===================== */
async function startGIDSScan() {
    try {
        const types = Array.from(document.querySelectorAll('input[name="impersonationType"]:checked')).map(cb => cb.value);
        if (!types.length) { alert('Select at least one service'); return; }

        document.getElementById('gids-progressPanel').style.display = 'block';
        document.getElementById('gids-resultsPanel').style.display = 'none';
        document.getElementById('gids-progressText').textContent = 'Initializing scan...';
        document.getElementById('gids-progressFill').style.width = '0%';
        document.getElementById('gids-progressPercent').textContent = '0%';
        startECG('ecgCanvas2');

        const res = await fetch('/api/scan/government-impersonation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ impersonation_types: types })
        });
        const result = await res.json();
        if (res.ok) {
            document.getElementById('gids-scanId').textContent = result.scan_id;
            document.getElementById('gids-progressText').textContent = 'Scanning for government impersonation sites…';
            pollGIDSScanStatus(result.scan_id);
        } else {
            alert('Error: ' + result.detail);
            document.getElementById('gids-progressPanel').style.display = 'none';
        }
    } catch (e) {
        alert('Error: ' + e.message);
        document.getElementById('gids-progressPanel').style.display = 'none';
    }
}

let gidsPollInterval;
function pollGIDSScanStatus(scanId) {
    let progress = 0;
    gidsPollInterval = setInterval(async () => {
        try {
            const res = await fetch(`/api/scan/${scanId}/government-impersonation`);
            const data = await res.json();
            if (data.status === 'in_progress') {
                progress = Math.min(progress + 15, 85);
                document.getElementById('gids-progressFill').style.width = progress + '%';
                document.getElementById('gids-progressPercent').textContent = Math.round(progress) + '%';
                document.getElementById('gids-scanStatus').textContent = 'Scanning…';
                updateScanPhases('gidsPhases', progress);
            } else if (data.status === 'completed') {
                clearInterval(gidsPollInterval);
                document.getElementById('gids-progressFill').style.width = '100%';
                document.getElementById('gids-progressPercent').textContent = '100%';
                document.getElementById('gids-progressText').textContent = 'Scan completed!';
                document.getElementById('gids-scanStatus').textContent = 'Completed';
                document.getElementById('gids-findingsCount').textContent = data.results_count;
                stopECG('ecgCanvas2');
                setTimeout(() => displayGIDSResults(data), 800);
            } else if (data.status === 'failed') {
                clearInterval(gidsPollInterval);
                document.getElementById('gids-progressFill').style.width = '100%';
                document.getElementById('gids-progressPercent').textContent = '100%';
                document.getElementById('gids-progressText').textContent = 'Scan finished (no threats found)';
                document.getElementById('gids-scanStatus').textContent = 'Done';
                stopECG('ecgCanvas2');
                setTimeout(() => displayGIDSResults(data), 800);
            }
            document.getElementById('gids-findingsCount').textContent = data.results_count;
        } catch (e) { console.error(e); }
    }, 3000);
}

function displayGIDSResults(data) {
    document.getElementById('gids-progressPanel').style.display = 'none';
    document.getElementById('gids-resultsPanel').style.display = 'block';

    // Cache the scan results for recent scans access
    scanResultsCache[data.scan_id] = {
        type: 'module2',
        data: data
    };

    // ✅ SET THE SCAN ID SO MAIN BUTTONS CAN FIND IT
    document.getElementById('gids-scanId').textContent = data.scan_id;

    const findings = data.findings || [];
    const rb = data.risk_breakdown || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

    document.getElementById('gids-resultsSummary').innerHTML = `
        <h4>Scan Summary</h4>
        <p><strong>Scan ID:</strong> ${data.scan_id}</p>
        <p><strong>Status:</strong> ${data.status}</p>
        <p><strong>Total Threats:</strong> ${data.results_count}</p>
        <div class="risk-breakdown">
            <span class="risk-critical">Critical: ${rb.CRITICAL}</span>
            <span class="risk-high">High: ${rb.HIGH}</span>
            <span class="risk-medium">Medium: ${rb.MEDIUM}</span>
            <span class="risk-low">Low: ${rb.LOW}</span>
        </div>
    `;

    window.allGIDSResults = findings;
    displayGIDSResultsTable(findings);
    loadRecentScans();
}

function displayGIDSResultsTable(results) {
    const tbody = document.getElementById('gids-resultsTableBody');
    tbody.innerHTML = '';
    if (!results.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No government impersonation threats detected.</td></tr>';
        return;
    }
    const riskMap = { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow)', LOW: 'var(--green)' };
    results.forEach(r => {
        const row = document.createElement('tr');
        row.setAttribute('data-risk', r.risk_level);
        row.innerHTML = `
            <td><strong>${r.impersonation_type}</strong></td>
            <td><a href="${r.url}" target="_blank">${r.domain}</a></td>
            <td style="color:${riskMap[r.risk_level] || 'var(--text-secondary)'};font-weight:700">${r.risk_level}</td>
            <td><strong>${r.confidence ? r.confidence.toFixed(1) : '0'}%</strong></td>
            <td><small>${(r.threat_details || '').substring(0, 100)}</small></td>
        `;
        tbody.appendChild(row);
    });
}

function filterGIDSResults(level) {
    document.querySelectorAll('.filter-pills .pill').forEach(p => p.classList.remove('active'));
    event.target.classList.add('active');
    let filtered = window.allGIDSResults || [];
    if (level !== 'all') filtered = filtered.filter(r => r.risk_level === level);
    displayGIDSResultsTable(filtered);
}

function exportGIDSResults() {
    const results = window.allGIDSResults || [];
    let csv = ['Impersonation Type,Domain,URL,Risk Level,Confidence %,Indicators,Threat Details'];
    results.forEach(r => {
        csv.push(`"${r.impersonation_type}","${r.domain}","${r.url}","${r.risk_level}","${r.confidence}","${(r.indicators||[]).join('; ')}","${r.threat_details}"`);
    });
    const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `gids_results_${Date.now()}.csv`;
    a.click();
}

/* ---------- Send Abuse Report (Module 2) ---------- */
async function sendAbuseReport() {
    try {
        const scanId = document.getElementById('gids-scanId').textContent;
        if (!scanId || scanId === '—') {
            alert('❌ No active scan found. Please complete a scan first.');
            return;
        }
        
        // Get all detected impersonation types from the results
        const results = window.allGIDSResults || [];
        const impersonationTypes = new Set();
        
        results.forEach(r => {
            if (r.impersonation_type) {
                impersonationTypes.add(r.impersonation_type);
            }
        });
        
        if (impersonationTypes.size === 0) {
            alert('❌ No impersonation threats detected in results. Check scan completed successfully.');
            return;
        }
        
        const typeArray = Array.from(impersonationTypes);
        let message = '⚠️ ABUSE REPORT - GOVERNMENT IMPERSONATION\n\nDetected Threat Types:\n';
        typeArray.forEach(type => message += `  • ${type.replace(/_/g, ' ').toUpperCase()}\n`);
        message += `\nSend abuse reports for detected government impersonation sites to CERT-In?`;
        
        if (!confirm(message)) {
            return;
        }
        
        let successCount = 0;
        let failureCount = 0;
        
        for (const type of typeArray) {
            try {
                const response = await fetch('/api/scan/send-abuse-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        scan_id: parseInt(scanId),
                        impersonation_type: type
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    successCount++;
                    console.log(`✅ Abuse report sent for ${type}`);
                } else {
                    const errData = await response.json();
                    failureCount++;
                    console.error(`Failed to send abuse report for ${type}:`, errData.detail || 'Unknown error');
                }
            } catch (error) {
                failureCount++;
                console.error(`Error sending abuse report for ${type}:`, error.message);
            }
        }
        
        const message2 = `📧 ABUSE REPORTS SENT\n\n✅ Successful: ${successCount}\n❌ Failed: ${failureCount}\n\nAll government impersonation abuse reports have been submitted to CERT-In for immediate investigation and takedown action.`;
        alert(message2);
        
    } catch (error) {
        alert('Error: ' + (error.message || 'Unknown error occurred'));
    }
}

function resetGIDSScan() {
    document.getElementById('gids-progressPanel').style.display = 'none';
    document.getElementById('gids-resultsPanel').style.display = 'none';
    document.getElementById('gids-progressFill').style.width = '0%';
    window.allGIDSResults = [];
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ===================== INIT ===================== */
document.addEventListener('DOMContentLoaded', () => {
    // Create mobile overlay
    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    overlay.onclick = toggleSidebar;
    document.body.appendChild(overlay);

    loadRecentScans();
    checkHealth();
    initCyberCanvas();
});

/* ===================== CYBER PARTICLE NETWORK ===================== */
function initCyberCanvas() {
    const canvas = document.getElementById('cyberCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let w, h, particles, mouse;
    const PARTICLE_COUNT = 60;
    const CONNECTION_DIST = 140;
    const MOUSE_DIST = 180;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }

    mouse = { x: -9999, y: -9999 };
    window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
    window.addEventListener('resize', resize);

    class Particle {
        constructor() {
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            this.vx = (Math.random() - 0.5) * 0.4;
            this.vy = (Math.random() - 0.5) * 0.4;
            this.radius = Math.random() * 1.5 + 0.5;
        }
        update() {
            this.x += this.vx;
            this.y += this.vy;
            if (this.x < 0 || this.x > w) this.vx *= -1;
            if (this.y < 0 || this.y > h) this.vy *= -1;
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 212, 170, 0.35)';
            ctx.fill();
        }
    }

    function init() {
        resize();
        particles = [];
        for (let i = 0; i < PARTICLE_COUNT; i++) {
            particles.push(new Particle());
        }
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            // Particle-to-particle connections
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < CONNECTION_DIST) {
                    const alpha = (1 - dist / CONNECTION_DIST) * 0.12;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 212, 170, ${alpha})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
            // Mouse proximity glow
            const mx = particles[i].x - mouse.x;
            const my = particles[i].y - mouse.y;
            const md = Math.sqrt(mx * mx + my * my);
            if (md < MOUSE_DIST) {
                const alpha = (1 - md / MOUSE_DIST) * 0.25;
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(mouse.x, mouse.y);
                ctx.strokeStyle = `rgba(0, 212, 170, ${alpha})`;
                ctx.lineWidth = 0.8;
                ctx.stroke();
                // Glow node near cursor
                ctx.beginPath();
                ctx.arc(particles[i].x, particles[i].y, particles[i].radius + 2, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(0, 212, 170, ${alpha * 0.5})`;
                ctx.fill();
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        particles.forEach(p => { p.update(); p.draw(); });
        drawConnections();
        requestAnimationFrame(animate);
    }

    init();
    animate();
}

/* ===================== SCAN MONITOR ANIMATION ===================== */
const scanMonitors = {};
const scanTimers = {};

function startScanTimer(timerId) {
    const start = Date.now();
    scanTimers[timerId] = setInterval(() => {
        const elapsed = Math.floor((Date.now() - start) / 1000);
        const el = document.getElementById(timerId);
        if (el) el.textContent = String(Math.floor(elapsed / 60)).padStart(2, '0') + ':' + String(elapsed % 60).padStart(2, '0');
    }, 1000);
}
function stopScanTimer(timerId) {
    if (scanTimers[timerId]) { clearInterval(scanTimers[timerId]); delete scanTimers[timerId]; }
}

function updateScanPhases(containerId, progress) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const phases = container.querySelectorAll('.phase');
    const connectors = container.querySelectorAll('.phase-connector');
    const thresholds = [0, 25, 50, 75];
    phases.forEach((p, i) => {
        p.classList.remove('active', 'completed');
        if (progress >= 100) { p.classList.add('completed'); }
        else if (progress >= thresholds[i] && (i === 3 || progress < thresholds[i + 1])) { p.classList.add('active'); }
        else if (progress >= thresholds[i]) { p.classList.add('completed'); }
    });
    connectors.forEach((c, i) => { c.classList.toggle('filled', progress > thresholds[i + 1]); });
}

function startECG(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 2;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const padding = { top: 26, bottom: 20, left: 0, right: 0 };
    const graphH = h - padding.top - padding.bottom;
    const graphW = w;
    const maxPoints = Math.floor(graphW / 2);

    // Professional cybersecurity theme colors
    const accent = '#00d4aa';
    const accentGlow = 'rgba(0,212,170,.35)';
    const fillTop = 'rgba(0,212,170,.14)';
    const fillBot = 'rgba(0,212,170,.01)';
    const gridColor = 'rgba(255,255,255,.035)';
    const gridMajor = 'rgba(255,255,255,.07)';
    const labelColor = 'rgba(255,255,255,.25)';
    const bgColor = '#0f1117';

    const dataPoints = [];
    let baseLevel = 0.3 + Math.random() * 0.3;
    let targetLevel = baseLevel;
    let currentLevel = baseLevel;
    let tick = 0;
    let itemsScanned = 0;
    let animId;

    function genValue() {
        tick++;
        if (tick % 50 === 0) targetLevel = 0.15 + Math.random() * 0.65;
        currentLevel += (targetLevel - currentLevel) * 0.04;
        const noise = Math.sin(tick * 0.12) * 0.06 + Math.sin(tick * 0.05) * 0.1 + (Math.random() - 0.5) * 0.04;
        itemsScanned += Math.floor(Math.random() * 3);
        return Math.max(0.05, Math.min(1, currentLevel + noise));
    }

    function draw() {
        dataPoints.push(genValue());
        if (dataPoints.length > maxPoints) dataPoints.shift();

        ctx.fillStyle = bgColor;
        ctx.fillRect(0, 0, w, h);

        // Horizontal grid
        const rows = 4;
        for (let i = 0; i <= rows; i++) {
            const y = padding.top + (graphH / rows) * i;
            ctx.strokeStyle = (i === 0 || i === rows) ? gridMajor : gridColor;
            ctx.lineWidth = 0.5;
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }

        // Vertical grid (scrolling)
        const spacing = 50;
        const offset = (tick * 1.5) % spacing;
        ctx.strokeStyle = gridColor; ctx.lineWidth = 0.5;
        for (let gx = w - offset; gx >= 0; gx -= spacing) {
            ctx.beginPath(); ctx.moveTo(gx, padding.top); ctx.lineTo(gx, padding.top + graphH); ctx.stroke();
        }

        if (dataPoints.length < 2) { animId = requestAnimationFrame(draw); return; }

        const stepX = graphW / maxPoints;
        const startX = (maxPoints - dataPoints.length) * stepX;

        // Area fill
        const grad = ctx.createLinearGradient(0, padding.top, 0, padding.top + graphH);
        grad.addColorStop(0, fillTop); grad.addColorStop(1, fillBot);

        ctx.beginPath();
        ctx.moveTo(startX, padding.top + graphH);
        for (let i = 0; i < dataPoints.length; i++) {
            const px = startX + i * stepX;
            const py = padding.top + graphH - dataPoints[i] * graphH;
            if (i === 0) ctx.lineTo(px, py);
            else {
                const prevX = startX + (i - 1) * stepX;
                const prevY = padding.top + graphH - dataPoints[i - 1] * graphH;
                ctx.bezierCurveTo((prevX + px) / 2, prevY, (prevX + px) / 2, py, px, py);
            }
        }
        ctx.lineTo(startX + (dataPoints.length - 1) * stepX, padding.top + graphH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // Line
        ctx.beginPath();
        for (let i = 0; i < dataPoints.length; i++) {
            const px = startX + i * stepX;
            const py = padding.top + graphH - dataPoints[i] * graphH;
            if (i === 0) ctx.moveTo(px, py);
            else {
                const prevX = startX + (i - 1) * stepX;
                const prevY = padding.top + graphH - dataPoints[i - 1] * graphH;
                ctx.bezierCurveTo((prevX + px) / 2, prevY, (prevX + px) / 2, py, px, py);
            }
        }
        ctx.strokeStyle = accent;
        ctx.lineWidth = 1.5;
        ctx.shadowColor = accentGlow;
        ctx.shadowBlur = 6;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Glow dot on latest point
        const lastX = startX + (dataPoints.length - 1) * stepX;
        const lastY = padding.top + graphH - dataPoints[dataPoints.length - 1] * graphH;
        ctx.beginPath(); ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
        ctx.fillStyle = accent; ctx.fill();
        ctx.beginPath(); ctx.arc(lastX, lastY, 6, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,212,170,.18)'; ctx.fill();

        // Header label
        ctx.fillStyle = labelColor;
        ctx.font = '600 9px Inter, system-ui, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText('SCAN ACTIVITY', 10, 15);

        // Items counter
        ctx.fillStyle = accent;
        ctx.font = '700 11px Inter, system-ui, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(itemsScanned + ' items analyzed', w - 10, 15);

        // Time axis
        ctx.fillStyle = labelColor;
        ctx.font = '9px Inter, system-ui, sans-serif';
        ctx.textAlign = 'center';
        const interval = Math.floor(maxPoints / 5);
        for (let i = 0; i < dataPoints.length; i += interval) {
            const secs = Math.floor((dataPoints.length - i) * 0.1);
            ctx.fillText('-' + secs + 's', startX + i * stepX, h - 4);
        }
        ctx.fillText('now', startX + (dataPoints.length - 1) * stepX, h - 4);

        animId = requestAnimationFrame(draw);
    }

    // Start timer for the associated panel
    const timerId = canvasId === 'ecgCanvas' ? 'scanTimer' : 'gids-scanTimer';
    startScanTimer(timerId);

    draw();
    scanMonitors[canvasId] = { animId, ctx, w, h };
}

function stopECG(canvasId) {
    const instance = scanMonitors[canvasId];
    if (instance) {
        cancelAnimationFrame(instance.animId);
        const { ctx, w, h } = instance;

        // Clean completion background
        ctx.fillStyle = '#0f1117';
        ctx.fillRect(0, 0, w, h);

        // Subtle grid
        const graphH = h - 46;
        ctx.strokeStyle = 'rgba(255,255,255,.04)';
        ctx.lineWidth = 0.5;
        for (let gy = 26; gy <= 26 + graphH; gy += graphH / 4) {
            ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(w, gy); ctx.stroke();
        }

        // Shield + checkmark
        const cx = w / 2, cy = h / 2;
        ctx.beginPath();
        ctx.arc(cx, cy, 18, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,212,170,.08)';
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,212,170,.4)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(cx - 6, cy);
        ctx.lineTo(cx - 2, cy + 5);
        ctx.lineTo(cx + 7, cy - 5);
        ctx.strokeStyle = '#00d4aa';
        ctx.lineWidth = 2;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();

        ctx.fillStyle = 'rgba(0,212,170,.45)';
        ctx.font = '600 10px Inter, system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('ANALYSIS COMPLETE', cx, cy + 34);

        delete scanMonitors[canvasId];
    }

    // Stop associated timer
    const timerId = canvasId === 'ecgCanvas' ? 'scanTimer' : 'gids-scanTimer';
    stopScanTimer(timerId);

    // Mark all phases complete
    const phaseId = canvasId === 'ecgCanvas' ? 'scanPhases' : 'gidsPhases';
    updateScanPhases(phaseId, 100);
}
