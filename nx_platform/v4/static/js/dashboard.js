document.addEventListener('DOMContentLoaded', function() {
    // State
    let activityChart = null;
    let distributionChart = null;
    let lastLogCount = 0;
    let jobsLimit = 15;
    let activitiesLimit = 15;
    let lastJobsContent = "";
    let lastActivitiesContent = "";
    
    // Elements
    const jobsTableBody = document.querySelector('#jobsTable tbody');
    const aiFeed = document.getElementById('ai-feed');
    const btnStartScan = document.getElementById('btn-start-scan');
    const btnLoadMoreJobs = document.getElementById('btn-load-more-jobs');
    const btnLoadMoreActivities = document.getElementById('btn-load-more-activities');
    const intelMixTableBody = document.querySelector('#intelMixTable tbody');
    const globalVaultBody = document.getElementById('globalVaultBody');
    const vaultCount = document.getElementById('vault-count');
    const findingsGallery = document.getElementById('findingsGallery');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');
    const aiActivityCards = document.getElementById('ai-activity-cards');
    const toolOutputAccordion = document.getElementById('toolOutputAccordion');
    const filterImportance = document.getElementById('filter-importance');
    const aiSearch = document.getElementById('aiSearch');
    const jobSearch = document.getElementById('jobSearch');
    const btnExpandAll = document.getElementById('btn-expand-all');

    let currentJobId = null;
    let toolSortOrder = 'desc';

    btnLoadMoreJobs.onclick = function() {
        jobsLimit += 15;
        fetchScans();
    };

    btnLoadMoreActivities.onclick = function() {
        activitiesLimit += 15;
        fetchAIActivities();
    };

    filterImportance.onchange = fetchAIActivities;
    aiSearch.oninput = fetchAIActivities;
    jobSearch.oninput = fetchScans;

    btnExpandAll.onclick = function() {
        const buttons = toolOutputAccordion.querySelectorAll('.accordion-button.collapsed');
        buttons.forEach(btn => btn.click());
    };

    if (sidebarToggle) {
        sidebarToggle.onclick = function() {
            sidebar.classList.toggle('show');
        };
    }

    // Init Charts
    function initCharts() {
        // Activity Line Chart
        const chartEl = document.getElementById('activityChart');
        if (!chartEl) return;
        
        const ctx1 = chartEl.getContext('2d');
        activityChart = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'AI Requests',
                    data: [],
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: '#333' } },
                    x: { grid: { color: '#333' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // API Calls
    async function fetchStats() {
        try {
            // Add a small delay to avoid overwhelming the server on reload
            const resp = await fetch('/api/v1/reports/stats');
            if (!resp.ok) throw new Error('Stats fetch failed');
            const data = await resp.json();
            
            document.getElementById('stat-total-scans').textContent = data.total_scans || 0;
            document.getElementById('stat-total-findings').textContent = data.total_findings || 0;
            document.getElementById('stat-success-rate').textContent = (data.success_rate || 0).toFixed(1) + '%';
            document.getElementById('stat-success-progress').style.width = (data.success_rate || 0) + '%';
            document.getElementById('stat-avg-response').textContent = (data.avg_response_time || 0).toFixed(0) + 'ms';
            
            const counts = data.activity_counts || {};
            const totalAIRequests = (counts.chat || 0) + (counts.analyze || 0) + (counts.exploit || 0) + 
                                    (counts.think || 0) + (counts.plan || 0) + (counts.observe || 0);
            
            document.getElementById('report-total-requests').textContent = totalAIRequests;
            
            // Update chart data
            const now = new Date();
            activityChart.data.labels.push(now.toLocaleTimeString());
            activityChart.data.datasets[0].data.push(totalAIRequests);
            
            if (activityChart.data.labels.length > 10) {
                activityChart.data.labels.shift();
                activityChart.data.datasets[0].data.shift();
            }
            activityChart.update();

        } catch (err) {
            console.warn('Dashboard stats currently unavailable (server might be busy).');
        }
    }

    async function fetchScans() {
        try {
            const search = jobSearch ? jobSearch.value.toLowerCase() : "";
            const resp = await fetch(`/api/v1/scans?limit=${jobsLimit}`);
            let jobs = await resp.json();
            
            // Collect all findings for Global Vault
            const allFindings = [];
            jobs.forEach(j => {
                // Add legacy findings
                if (j.findings && j.findings.length > 0) {
                    j.findings.forEach(f => {
                        allFindings.push({...f, target: j.target});
                    });
                }
                // Add structured findings (from V4 AI Engine)
                if (j.structured_vulnerabilities && j.structured_vulnerabilities.length > 0) {
                    j.structured_vulnerabilities.forEach(v => {
                        // Map to a common format if needed, or just push with target
                        allFindings.push({
                            ...v, 
                            target: j.target,
                            url: v.url || (v.port ? `${v.service || 'svc'} on ${v.port}` : null)
                        });
                    });
                }
            });
            renderGlobalVault(allFindings);

            if (search) {
                jobs = jobs.filter(j => j.target.toLowerCase().includes(search) || j.status.toLowerCase().includes(search));
            }
            
            // Only update if data changed (simple check)
            const newContent = jobs.map(job => job.id + job.status).join(',');
            if (lastJobsContent === newContent) return;
            lastJobsContent = newContent;

            jobsTableBody.innerHTML = '';
            if (jobs.length === 0) {
                jobsTableBody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">Belum ada riwayat pemindaian.</td></tr>';
                return;
            }

            jobs.forEach(job => {
                const row = document.createElement('tr');
                const startTime = new Date(job.start_time).toLocaleString();
                const statusClass = job.status === 'running' ? 'text-warning' : (job.status === 'completed' ? 'text-success' : 'text-danger');
                const aiMode = (job.metrics && job.metrics.ai_mode_selected) ? job.metrics.ai_mode_selected.toUpperCase() : 'AUTO';
                
                row.innerHTML = `
                    <td class="text-truncate" style="max-width: 200px;" title="${job.target}">
                        <div class="fw-bold">${job.target}</div>
                        <div class="x-small text-secondary"><i class="bi bi-cpu"></i> ${aiMode}</div>
                    </td>
                    <td><span class="${statusClass}"><i class="bi bi-circle-fill small me-1"></i> ${job.status}</span></td>
                    <td><span class="badge bg-danger">${job.findings.length}</span></td>
                    <td class="small text-secondary">${startTime}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-info" onclick="viewJob('${job.id}')" title="View Details"><i class="bi bi-eye"></i></button>
                        ${job.status === 'running' ? `<button class="btn btn-sm btn-outline-danger" onclick="stopJob('${job.id}')" title="Stop Scan"><i class="bi bi-stop-circle"></i></button>` : ''}
                    </td>
                `;
                jobsTableBody.appendChild(row);
            });
        } catch (err) {
            console.error('Error fetching scans:', err);
        }
    }

    async function fetchAIActivities() {
        try {
            const importance = filterImportance.value;
            const search = aiSearch.value.toLowerCase();
            const resp = await fetch(`/api/v1/activities?limit=${activitiesLimit}`);
            let activities = await resp.json();
            
            // Auto-filter logic
            activities = activities.filter(act => {
                const matchesSearch = act.prompt.toLowerCase().includes(search) || act.response.toLowerCase().includes(search);
                const isImportant = importance === 'all' || 
                                   (importance === 'high' && (act.activity_type === 'exploit' || act.status === 'failure')) ||
                                   (importance === 'medium' && (act.activity_type === 'think' || act.activity_type === 'plan'));
                return matchesSearch && isImportant;
            });

            // 1. Update Intelligence Mix Table (Top 5 Unique Actions)
            renderIntelMix(activities);

            // 2. Update Feed (Sidebar)
            const feedContent = activities.map(act => act.id + act.status).join(',');
            if (lastActivitiesContent !== feedContent) {
                const wasAtBottom = aiFeed.scrollHeight - aiFeed.scrollTop <= aiFeed.clientHeight + 10;
                
                lastActivitiesContent = feedContent;
                aiFeed.innerHTML = '';
                if (activities.length === 0) {
                    aiFeed.innerHTML = '<div class="text-center text-secondary py-5">No activities match filters.</div>';
                } else {
                    activities.forEach(act => renderFeedItem(act));
                }

                // Auto-scroll if was at bottom
                if (wasAtBottom) {
                    aiFeed.scrollTop = aiFeed.scrollHeight;
                }
            }

            // 3. Update Strategic Cards (Main Area)
            renderStrategicCards(activities);
            
        } catch (err) {
            console.error('Error fetching activities:', err);
        }
    }

    function renderIntelMix(activities) {
        // Clear table body to prevent downward expansion
        intelMixTableBody.innerHTML = '';
        
        // Take only top 5 unique activities (based on activity_type + status)
        const seen = new Set();
        const uniqueActivities = activities.filter(act => {
            const key = act.activity_type + act.status + act.prompt.substring(0, 20);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        }).slice(0, 5);

        if (uniqueActivities.length === 0) {
            intelMixTableBody.innerHTML = '<tr><td colspan="3" class="text-center text-secondary py-3">No recent intel.</td></tr>';
            return;
        }

        uniqueActivities.forEach(act => {
            const time = new Date(act.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const statusColor = act.status === 'success' ? 'text-success' : 'text-danger';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="ps-4 fw-bold text-info">${act.activity_type.toUpperCase()}</td>
                <td><span class="${statusColor}">${act.status.toUpperCase()}</span></td>
                <td class="text-end pe-4 text-secondary">${time}</td>
            `;
            intelMixTableBody.appendChild(row);
        });
    }

    function renderFeedItem(act) {
        const time = new Date(act.timestamp).toLocaleTimeString();
        const item = document.createElement('div');
        item.className = 'mb-3 p-3 bg-dark border-start border-3 border-info rounded shadow-sm interaction-item';
        item.style.cursor = 'pointer';
        item.onclick = () => showAIDetails(act);
        
        item.innerHTML = `
            <div class="d-flex justify-content-between mb-1">
                <span class="badge bg-info text-dark text-uppercase" style="font-size: 0.65rem;">${act.activity_type}</span>
                <small class="text-secondary" style="font-size: 0.7rem;">${time}</small>
            </div>
            <div class="text-truncate small mb-1" style="max-width: 100%;">${act.prompt}</div>
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-success" style="font-size: 0.7rem;">${act.model_used}</small>
                <small class="text-secondary" style="font-size: 0.7rem;">${act.duration.toFixed(0)}ms</small>
            </div>
        `;
        aiFeed.appendChild(item);
    }

    function renderStrategicCards(activities) {
        // Only show top 4 important activities as cards
        const importantOnes = activities
            .filter(a => a.activity_type !== 'chat')
            .slice(0, 4);

        if (importantOnes.length === 0) {
            aiActivityCards.innerHTML = '<div class="col-12 text-center py-4 text-secondary">Belum ada aktivitas strategis terdeteksi.</div>';
            return;
        }

        aiActivityCards.innerHTML = '';
        importantOnes.forEach(act => {
            const importanceClass = (act.activity_type === 'exploit') ? 'importance-high' : 'importance-medium';
            const statusIcon = act.status === 'success' ? 'bi-check-circle-fill text-success' : 'bi-exclamation-circle-fill text-danger';
            const time = new Date(act.timestamp).toLocaleTimeString();
            
            const col = document.createElement('div');
            col.className = 'col-md-6 col-lg-3';
            
            // Create element to avoid JSON.stringify in HTML attributes
            const card = document.createElement('div');
            card.className = `card bg-black border-secondary h-100 ai-card ${importanceClass}`;
            card.onclick = () => showAIDetails(act);
            
            card.innerHTML = `
                <div class="card-body p-3">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <span class="badge bg-dark border border-secondary text-info">${act.activity_type.toUpperCase()}</span>
                        <i class="bi ${statusIcon}"></i>
                    </div>
                    <h6 class="card-title text-light small mb-1">Target: ${act.job_id ? 'Job Active' : 'Global'}</h6>
                    <p class="card-text text-secondary x-small mb-2 text-truncate-2">${act.prompt}</p>
                    <div class="d-flex justify-content-between align-items-center mt-auto">
                        <span class="x-small text-secondary"><i class="bi bi-clock"></i> ${time}</span>
                        <span class="x-small text-info">${act.duration.toFixed(0)}ms</span>
                    </div>
                </div>
            `;
            col.appendChild(card);
            aiActivityCards.appendChild(col);
        });
    }

    window.viewJob = async function(jobId) {
        currentJobId = jobId;
        try {
            const resp = await fetch(`/api/v1/scan/${jobId}`);
            const data = await resp.json();
            
            renderToolOutputs(data.logs);
            
            // NEW: Prioritize structured vulnerabilities from NX-AI Advanced Engine
            const allFindings = [];
            
            // Add structured findings if they exist (V4.1+)
            if (data.structured_vulnerabilities && data.structured_vulnerabilities.length > 0) {
                data.structured_vulnerabilities.forEach(v => {
                    allFindings.push({
                        type: v.name || v.vuln_name || 'VULN',
                        severity: v.severity || 'medium',
                        description: v.description || 'Verified by NX-AI Engine.',
                        url: `${v.service} on port ${v.port}`,
                        confidence: 1.0, // AI verified
                        fix: v.fixes ? v.fixes.map(f => f.fix_text).join('; ') : null
                    });
                });
            }
            
            // Add legacy findings if they exist
            if (data.findings && data.findings.length > 0) {
                data.findings.forEach(f => {
                    // Avoid duplicates if already in structured findings
                    const isDup = allFindings.some(af => af.url === f.url && af.type === f.type);
                    if (!isDup) allFindings.push(f);
                });
            }
            
            renderVerifiedFindings(allFindings);
            
            // Switch to findings tab automatically if there are any
            if (allFindings.length > 0) {
                const tab = new bootstrap.Tab(document.getElementById('findings-tab'));
                tab.show();
            } else {
                const tab = new bootstrap.Tab(document.getElementById('logs-tab'));
                tab.show();
            }
            
            // Highlight the row in the table
            jobsTableBody.querySelectorAll('tr').forEach(tr => tr.classList.remove('table-active'));
            document.getElementById('explorerTabs').scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
            console.error('Error viewing job:', err);
        }
    };

    function renderVerifiedFindings(findings) {
        if (!findings || findings.length === 0) {
            findingsGallery.innerHTML = `
                <div class="col-12 text-center py-5 text-secondary opacity-50">
                    <i class="bi bi-shield-check fs-1 mb-2 d-block"></i>
                    <p>No verified vulnerabilities reported yet.</p>
                </div>`;
            return;
        }

        findingsGallery.innerHTML = '';
        findings.forEach(vuln => {
            // Filter out system errors or extremely low confidence findings
            if (vuln.confidence !== undefined && vuln.confidence <= 0.05) return;
            if (vuln.is_system_error) return;

            const severity = (vuln.severity || 'medium').toLowerCase();
            const severityClass = severity === 'high' || severity === 'critical' ? 'danger' : 
                                 (severity === 'medium' ? 'warning' : 'info');
            
            const card = document.createElement('div');
            card.className = 'col-md-6 col-xl-4';
            
            // Handle URL display and fix text
            const displayUrl = vuln.url || 'N/A';
            const displayFix = vuln.fix ? `<div class="mt-2 x-small text-success border-top border-secondary border-opacity-10 pt-1"><i class="bi bi-tools"></i> ${vuln.fix}</div>` : '';

            card.innerHTML = `
                <div class="card bg-black border-${severityClass} h-100 shadow-sm">
                    <div class="card-body p-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="badge bg-${severityClass}-soft text-${severityClass} x-small fw-bold">${(vuln.type || 'vuln').toUpperCase()}</span>
                            <span class="x-small text-secondary">${vuln.confidence ? (vuln.confidence * 100).toFixed(0) + '%' : '100%'} Confidence</span>
                        </div>
                        <h6 class="card-title text-light small text-truncate mb-1" title="${displayUrl}">${displayUrl}</h6>
                        <p class="card-text text-secondary x-small mb-2 text-truncate-2">${vuln.description || 'Verified vulnerability found.'}</p>
                        ${displayFix}
                        <div class="mt-auto pt-2 border-top border-secondary border-opacity-25 d-flex justify-content-between align-items-center">
                            <span class="x-small fw-bold text-${severityClass}">${severity.toUpperCase()}</span>
                            <button class="btn btn-xs btn-outline-secondary" onclick="copyToClipboard('${displayUrl}')"><i class="bi bi-clipboard"></i></button>
                        </div>
                    </div>
                </div>
            `;
            findingsGallery.appendChild(card);
        });
    }

    function renderGlobalVault(allFindings) {
        if (!globalVaultBody) return;
        
        if (allFindings.length === 0) {
            vaultCount.textContent = "0 VERIFIED VULNS";
            globalVaultBody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-5 text-secondary opacity-50">
                        <i class="bi bi-safe2 fs-1 mb-2 d-block"></i>
                        <p>Global Vault is empty. No universal findings detected across missions.</p>
                    </td>
                </tr>`;
            return;
        }

        vaultCount.textContent = `${allFindings.length} VERIFIED VULNS`;
        
        // Only update if findings count or IDs changed to prevent flickering
        const currentFingerprint = allFindings.map(f => f.url + f.type).join('|');
        if (this.lastVaultFingerprint === currentFingerprint) return;
        this.lastVaultFingerprint = currentFingerprint;

        globalVaultBody.innerHTML = '';
        allFindings
            .filter(f => !f.is_system_error && (f.confidence === undefined || f.confidence > 0.05))
            .slice(0, 15) // Show top 15 in vault
            .forEach(vuln => {
                const severity = (vuln.severity || 'low').toLowerCase();
                const severityClass = severity === 'high' || severity === 'critical' ? 'danger' : 
                                     (severity === 'medium' ? 'warning' : 'info');
            
            // Fallback logic for URL/Title to avoid 'undefined'
            const displayUrl = vuln.url || vuln.evidence || vuln.matched || vuln.value || vuln.target || 'N/A';
            const displayType = (vuln.type || vuln.name || 'vuln').toUpperCase();
            const confidence = vuln.confidence ? (vuln.confidence * 100).toFixed(0) : '100';

            const row = document.createElement('tr');
            row.className = 'border-bottom border-secondary border-opacity-10';
            row.innerHTML = `
                <td class="px-4 py-3">
                    <div class="d-flex align-items-center">
                        <div class="vuln-icon bg-${severityClass}-soft text-${severityClass} me-3 rounded-circle d-flex align-items-center justify-content-center" style="width: 32px; height: 32px;">
                            <i class="bi bi-bug-fill small"></i>
                        </div>
                        <div>
                            <div class="fw-bold text-light small">${displayType}</div>
                            <div class="x-small text-secondary text-truncate" style="max-width: 250px;">${vuln.description || 'Verified vulnerability found.'}</div>
                        </div>
                    </div>
                </td>
                <td class="py-3">
                    <div class="text-info x-small fw-medium text-truncate" style="max-width: 180px;" title="${displayUrl}">
                        ${displayUrl}
                    </div>
                    <div class="x-small text-secondary"><i class="bi bi-globe me-1"></i> ${vuln.target || 'Global'}</div>
                </td>
                <td class="py-3">
                    <span class="badge bg-${severityClass}-soft text-${severityClass} x-small fw-bold">${severity.toUpperCase()}</span>
                </td>
                <td class="py-3">
                    <div class="d-flex align-items-center">
                        <div class="progress bg-dark me-2" style="height: 4px; width: 40px;">
                            <div class="progress-bar bg-${severityClass}" style="width: ${confidence}%"></div>
                        </div>
                        <span class="x-small text-secondary">${confidence}%</span>
                    </div>
                </td>
                <td class="px-4 py-3 text-end">
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-secondary border-0" onclick="copyToClipboard('${displayUrl}')" title="Copy Evidence">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <button class="btn btn-outline-info border-0" onclick="alert('Analysis: ${vuln.description || 'No additional details available.'}')" title="AI Analysis">
                            <i class="bi bi-info-circle"></i>
                        </button>
                    </div>
                </td>
            `;
            globalVaultBody.appendChild(row);
        });
    }

    window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Copied to clipboard!');
        });
    };

    function renderToolOutputs(logs) {
        if (!logs || logs.length === 0) {
            toolOutputAccordion.innerHTML = '<div class="p-5 text-center text-secondary">Tidak ada output tools untuk job ini.</div>';
            return;
        }

        // Group logs by tool name [TOOL_NAME]
        const grouped = {};
        logs.forEach(line => {
            const match = line.match(/\[(\w+)\]/);
            const tool = match ? match[1] : 'SYSTEM';
            if (!grouped[tool]) grouped[tool] = [];
            grouped[tool].push(line);
        });

        toolOutputAccordion.innerHTML = '';
        Object.keys(grouped).forEach((tool, index) => {
            const toolLogs = grouped[tool].join('\n');
            const accordionId = `tool-${tool}-${index}`;
            
            const item = document.createElement('div');
            item.className = 'accordion-item';
            item.innerHTML = `
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${accordionId}">
                        <span class="badge bg-info text-dark badge-tool me-2">${tool}</span>
                        <span class="small">${grouped[tool].length} entries</span>
                    </button>
                </h2>
                <div id="${accordionId}" class="accordion-collapse collapse" data-bs-parent="#toolOutputAccordion">
                    <div class="accordion-body bg-black p-0">
                        <div class="d-flex justify-content-end p-2 border-bottom border-secondary">
                            <button class="btn btn-xs btn-outline-info me-2" onclick="downloadToolLog('${tool}', '${btoa(toolLogs)}')">
                                <i class="bi bi-download"></i> Download
                            </button>
                        </div>
                        <div class="tool-log-content">${toolLogs}</div>
                    </div>
                </div>
            `;
            toolOutputAccordion.appendChild(item);
        });
    }

    window.downloadToolLog = function(tool, base64Logs) {
        const logs = atob(base64Logs);
        const blob = new Blob([logs], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${tool}_output_${new Date().getTime()}.log`;
        a.click();
    };

    window.showAIDetails = function(act) {
        if (!act) return;
        if (typeof act === 'string') {
            try {
                act = JSON.parse(act);
            } catch(e) {
                console.error("Failed to parse act:", e);
                return;
            }
        }
        
        document.getElementById('ai-modal-prompt').textContent = act.prompt || 'N/A';
        document.getElementById('ai-modal-output').textContent = act.response || 'N/A';
        document.getElementById('ai-modal-model').textContent = act.model_used || 'N/A';
        document.getElementById('ai-modal-duration').textContent = (act.duration ? act.duration.toFixed(0) : '0') + 'ms';
        
        const modalEl = document.getElementById('aiModal');
        if (modalEl) {
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        }
    };

    async function fetchModels() {
        try {
            const resp = await fetch('/api/v1/ai/models');
            const data = await resp.json();
            const select = document.getElementById('ai-model');
            if (!select) return;

            select.innerHTML = '';
            if (data.models && data.models.length > 0) {
                data.models.forEach(model => {
                    const opt = document.createElement('option');
                    opt.value = model;
                    opt.textContent = model;
                    if (model.includes('deepseek-r1')) opt.selected = true;
                    select.appendChild(opt);
                });
            } else {
                select.innerHTML = '<option value="">No models found</option>';
            }
        } catch (err) {
            console.error('Error fetching models:', err);
        }
    }

    btnStartScan.onclick = async function() {
        const url = document.getElementById('target-url').value;
        const modeRadio = document.querySelector('input[name="ai_mode"]:checked');
        const mode = modeRadio ? modeRadio.value : 'true_ai';
        const model = document.getElementById('ai-model').value;
        const forceEnum = document.getElementById('force-enum').checked;
        
        if (!url) return alert('Masukkan URL target!');
        
        try {
            const resp = await fetch('/api/v1/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    url, 
                    ai_mode: mode, 
                    ai_model: model,
                    force_enum: forceEnum 
                })
            });
            const data = await resp.json();
            
            const modalEl = document.getElementById('scanModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
            
            // Refresh
            fetchScans();
            alert('Mission started successfully: ' + data.job_id);
        } catch (err) {
            alert('Gagal memulai scan: ' + err);
        }
    };

    window.stopJob = async function(jobId) {
        if (!confirm('Hentikan pemindaian ini?')) return;
        try {
            await fetch(`/api/v1/scan/${jobId}`, { method: 'DELETE' });
            fetchScans();
        } catch (err) {
            alert('Gagal menghentikan scan');
        }
    };

    // Loops
    initCharts();
    fetchModels(); // Fetch available models on load
    fetchStats().catch(e => console.error("Stats loop error:", e));
    fetchScans().catch(e => console.error("Scans loop error:", e));
    fetchAIActivities().catch(e => console.error("AI loop error:", e));
    
    setInterval(() => {
        fetchStats().catch(e => console.error("Stats interval error:", e));
        fetchScans().catch(e => console.error("Scans interval error:", e));
        fetchAIActivities().catch(e => console.error("AI interval error:", e));
    }, 5000);
});
