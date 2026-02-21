/* ===================================================================
   CyberShield — UI Logic
   =================================================================== */

const API_BASE_URL = '';

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

    if (module === 'module1') {
        m1.style.display = 'block';
        m2.style.display = 'none';
        nav1.classList.add('active');
        nav2.classList.remove('active');
        title.textContent = 'Sensitive Data Exposure Detection';
    } else {
        m1.style.display = 'none';
        m2.style.display = 'block';
        nav1.classList.remove('active');
        nav2.classList.add('active');
        title.textContent = 'Government Impersonation Detection';
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
        const badge = document.getElementById('healthBadge');
        if (data.status === 'healthy') {
            badge.querySelector('span').textContent = 'Healthy';
            badge.style.borderColor = 'rgba(81,207,102,.2)';
            badge.style.color = '#51cf66';
        }
    } catch {
        const badge = document.getElementById('healthBadge');
        badge.querySelector('span').textContent = 'Offline';
        badge.style.borderColor = 'rgba(255,77,106,.2)';
        badge.style.color = '#ff4d6a';
    }

    // Also check API-key configuration so the user sees an early warning
    try {
        const cfgRes = await fetch('/api/config/status');
        const cfg = await cfgRes.json();
        let banner = document.getElementById('configBanner');
        if (!cfg.configured) {
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'configBanner';
                banner.style.cssText =
                    'background:#2a1a00;border:1px solid #ff922b;color:#ffd8a8;' +
                    'padding:12px 18px;border-radius:8px;margin:12px 24px;font-size:14px;';
                const main = document.querySelector('main') || document.body;
                main.prepend(banner);
            }
            banner.innerHTML =
                '<strong>⚠️ Google API keys not configured.</strong> ' +
                'Search will use a fallback web-scraping mode which may be less reliable. ' +
                'For best results, copy <code>.env.example</code> to <code>.env</code>, add your keys, and restart the server.';
        } else if (cfg.mismatched) {
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'configBanner';
                banner.style.cssText =
                    'background:#1a2a00;border:1px solid #a9e34b;color:#d8f5a2;' +
                    'padding:12px 18px;border-radius:8px;margin:12px 24px;font-size:14px;';
                const main = document.querySelector('main') || document.body;
                main.prepend(banner);
            }
            banner.textContent =
                '⚠️ API key / Search Engine ID count mismatch — only ' +
                cfg.usable_pairs + ' pair(s) will be used.';
        } else if (banner) {
            banner.remove();
        }
    } catch { /* config endpoint unavailable — ignore */ }
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
        const sendEmail = document.getElementById('sendEmail').checked;

        const requestData = { data_types: dataTypes, file_types: fileTypes, domain, max_results: maxResults, send_email: sendEmail };

        document.getElementById('progressPanel').style.display = 'block';
        document.getElementById('resultsPanel').style.display = 'none';
        document.getElementById('progressText').textContent = 'Initializing scan...';
        document.getElementById('progressFill').style.width = '0%';

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
            document.getElementById('detectionsCount').textContent = data.results_count;

            if (data.status === 'in_progress') {
                progress = Math.min(progress + 10, 90);
                document.getElementById('progressFill').style.width = progress + '%';
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('progressText').textContent = 'Scan completed!';
                setTimeout(() => displayResults(data), 800);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('progressText').textContent = 'Scan finished (no results found)';
                setTimeout(() => displayResults(data), 800);
            }
        } catch (e) { console.error('Poll error:', e); }
    }, 3000);
}

function displayResults(data) {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';

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
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No sensitive data leaks detected.</td></tr>';
    } else {
        detections.forEach(urlItem => {
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
                item.onclick = () => viewScanDetails(scan.scan_id);
                const statusClass = scan.status === 'completed' ? 'completed' : scan.status === 'failed' ? 'failed' : 'in_progress';
                item.innerHTML = `
                    <strong>Scan #${scan.scan_id}</strong>
                    <span class="scan-item-status ${statusClass}">${scan.status}</span><br>
                    <span style="color:var(--text-secondary);font-size:.85rem">${scan.scan_type.replace(/_/g,' ')} &middot; ${scan.results_count} results</span><br>
                    <small>${new Date(scan.start_time).toLocaleString()}</small>
                `;
                list.appendChild(item);
            });
        } else {
            list.innerHTML = '<p class="empty-state">No recent scans yet — start your first scan above.</p>';
        }
    } catch (e) { console.error('Error loading recent scans:', e); }
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
            } else if (data.status === 'completed') {
                clearInterval(gidsPollInterval);
                document.getElementById('gids-progressFill').style.width = '100%';
                document.getElementById('gids-progressPercent').textContent = '100%';
                document.getElementById('gids-progressText').textContent = 'Scan completed!';
                document.getElementById('gids-scanStatus').textContent = 'Completed';
                document.getElementById('gids-findingsCount').textContent = data.results_count;
                setTimeout(() => displayGIDSResults(data), 800);
            } else if (data.status === 'failed') {
                clearInterval(gidsPollInterval);
                document.getElementById('gids-progressFill').style.width = '100%';
                document.getElementById('gids-progressPercent').textContent = '100%';
                document.getElementById('gids-progressText').textContent = 'Scan finished (no threats found)';
                document.getElementById('gids-scanStatus').textContent = 'Done';
                setTimeout(() => displayGIDSResults(data), 800);
            }
            document.getElementById('gids-findingsCount').textContent = data.results_count;
        } catch (e) { console.error(e); }
    }, 3000);
}

function displayGIDSResults(data) {
    document.getElementById('gids-progressPanel').style.display = 'none';
    document.getElementById('gids-resultsPanel').style.display = 'block';

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
