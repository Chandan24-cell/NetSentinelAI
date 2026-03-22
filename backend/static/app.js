// Configurable Backend URL (for dashboard compatibility)
const BACKEND_URL = '/';

let uploadedFilePath = null;
let alertsData = [];
let blockedIps = new Set();
let attackHistory = [];
let livePacketCount = 0;
let chart = null;

function uploadFile() {
    const fileInput = document.getElementById('csvFile');
    const status = document.getElementById('status');

    if (!fileInput.files || fileInput.files.length === 0) {
        status.textContent = 'No file selected!';
        return;
    }

    const file = fileInput.files[0];
    console.log('Uploaded file:', file.name);

    const formData = new FormData();
    formData.append('file', file);

    status.textContent = 'Uploading...';

    fetch(`${BACKEND_URL}/upload`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        status.textContent = data.message || 'File uploaded!';
        document.getElementById('runBtn').disabled = false;
        uploadedFilePath = data.path;
        console.log("Uploaded file path:", uploadedFilePath);
    })
    .catch(err => {
        console.error(err);
        status.textContent = 'Upload failed!';
    });
}

function runDetection() {
    const status = document.getElementById('status');
    if (!uploadedFilePath || typeof uploadedFilePath !== 'string' || uploadedFilePath.trim() === '') {
        status.textContent = 'Invalid file path. Please upload a file first.';
        console.error('Error: uploadedFilePath is invalid:', uploadedFilePath);
        return;
    }
    console.log('Sending file_path:', uploadedFilePath);

    status.textContent = 'Starting detection...';

    fetch(`${BACKEND_URL}/run`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path: uploadedFilePath})
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.error || `Server error: ${response.status}`);
            }).catch(() => {
                throw new Error(`Server error: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        status.textContent = data.message;
    })
    .catch(err => {
        console.error('Fetch error:', err);
        status.textContent = `Detection failed! Error: ${err.message}`;
    });
}

// Removed problematic onclick assignments - using inline event listeners in HTML

async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();
        alertsData = data;

        // Update active alerts (non-BENIGN)
        const activeCount = data.filter(a => a.predicted_label !== 'BENIGN').length;
        const el = document.getElementById('activeAlerts');
        if (el) el.textContent = activeCount;

        // Update DDoS count
        const ddosCount = data.filter(a => a.predicted_label.toLowerCase().includes('ddos')).length;
        const ddosEl = document.getElementById('ddosCount');
        if (ddosEl) ddosEl.textContent = ddosCount;

        // Update blocked count (simulate/add endpoint if needed)
        const blockedEl = document.getElementById('blockedCount');
        if (blockedEl) blockedEl.textContent = blockedIps.size;

        updateAlertsTable(data);
        updateTopAttackers();
        updateAttackChart(data);
    } catch (error) {
        console.error('fetchAlerts error:', error);
    }
}

function updateAlertsTable(data) {
    const tbody = document.querySelector('#alertsTable tbody') || document.getElementById('alertsTable');
    if (!tbody) return;

    tbody.innerHTML = '';
    data.slice(0, 50).forEach(alert => {  // Last 50
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${new Date(alert.time * 1000).toLocaleTimeString()}</td>
            <td>${alert.predicted_label}</td>
            <td>${alert.src_ip}</td>
            <td>${alert.dst_ip}</td>
            <td>${alert.protocol}</td>
            <td><button class="btn btn-sm btn-danger" onclick="blockIP('${alert.src_ip}')">Block</button></td>
        `;
    });
}

async function blockIP(ip) {
    if (ip === 'unknown' || blockedIps.has(ip)) return;
    try {
        const response = await fetch(`/api/block/${ip}`, {method: 'POST'});
        if (response.ok) {
            blockedIps.add(ip);
            fetchAlerts();  // Refresh
        }
    } catch (e) {
        console.error('Block IP error:', e);
    }
}

function updateTopAttackers() {
    const attackerCounts = {};
    alertsData.forEach(a => {
        if (a.src_ip && a.predicted_label !== 'BENIGN') {
            attackerCounts[a.src_ip] = (attackerCounts[a.src_ip] || 0) + 1;
        }
    });
    
    const sortedAttackers = Object.entries(attackerCounts)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10);
    
    const list = document.getElementById('attackerList');
    if (list) {
        list.innerHTML = '';
        sortedAttackers.forEach(([ip, count]) => {
            const item = document.createElement('li');
            item.className = 'list-group-item d-flex justify-content-between align-items-center';
            item.innerHTML = `<strong>${ip}</strong> <span class="badge bg-danger rounded-pill">${count}</span>`;
            const blockBtn = document.createElement('button');
            blockBtn.textContent = 'Block';
            blockBtn.className = 'btn btn-sm btn-danger ms-2';
            blockBtn.onclick = () => blockIP(ip);
            item.appendChild(blockBtn);
            list.appendChild(item);
        });
    }
}



function initChart() {
    const ctx = document.getElementById('attackChart');
    if (!ctx) return;
    if (chart) return;
    chart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220,53,69,0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true } }
        }
    });
}

function updateAttackChart(data) {
    initChart();

    // Aggregate by minute
    const timeBuckets = {};
    data.forEach(a => {
        if (a.predicted_label !== 'BENIGN') {
            const minute = new Date(a.time * 1000).toLocaleString('en-US', { minute: '2-digit', hour: '2-digit' });
            timeBuckets[minute] = (timeBuckets[minute] || 0) + 1;
        }
    });

    const labels = Object.keys(timeBuckets).sort();
    const values = labels.map(l => timeBuckets[l]);

    chart.data.labels = labels.slice(-10);  // Last 10 mins
    chart.data.datasets[0].data = values.slice(-10);
    chart.update('none');
}

// Disabled conflicting blockIP - HTML has inline blockIP using /api/block/${ip}

function updateLiveMetrics() {
    livePacketCount += Math.floor(Math.random() * 100) + 50;
    document.getElementById('livePackets') ? document.getElementById('livePackets').textContent = livePacketCount.toLocaleString() : null;
}

// JS disabled - HTML script is self-contained and auto-refreshes
