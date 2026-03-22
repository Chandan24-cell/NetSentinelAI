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

async function fetchThreatSummary() {
    try {
        const response = await fetch('/api/threat_summary');
        const data = await response.json();
        document.getElementById('topAttack').textContent = data.top_attack;
        document.getElementById('topIP').textContent = data.top_ip;
        document.getElementById('totalAlerts').textContent = data.total_alerts;
        document.getElementById('criticalCount').textContent = data.critical;
    } catch (error) {
        console.error('Threat summary error:', error);
    }
}

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
        updateAttackChart();
        updateAttackMap();
        fetchThreatSummary();
        fetchLivePackets();
        fetchNetworkTraffic();
    } catch (error) {
        console.error('fetchAlerts error:', error);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    initTrafficChart();
});

function getSeverityClass(label) {
    if (label.includes('DDoS') || label.includes('DoS')) return 'table-danger severity-critical';
    if (label.includes('PortScan') || label.includes('Scan')) return 'table-warning severity-medium';
    if (label.includes('Attack')) return 'table-warning severity-high';
    return 'table-info severity-low';
}

function getConfidenceColor(conf) {
    if (conf > 90) return 'confidence-high';
    if (conf > 70) return 'confidence-medium';
    return 'confidence-low';
}

function updateAlertsTable(data) {
    const tbody = document.querySelector('#alertsTable tbody') || document.getElementById('alertsTable');
    if (!tbody) return;

    tbody.innerHTML = '';
    data.slice(0, 50).forEach(alert => {  // Last 50
        const confidence = Math.floor(Math.random() * 30 + 70); // 70-99%
        const severityClass = getSeverityClass(alert.predicted_label || 'BENIGN');
        const confClass = getConfidenceColor(confidence);
        const row = tbody.insertRow();
        row.className = severityClass;
        row.innerHTML = `
            <td>${new Date(alert.time * 1000).toLocaleTimeString()}</td>
            <td><strong>${alert.predicted_label}</strong></td>
            <td class="${confClass}">${confidence}%</td>
            <td>${alert.src_ip || 'N/A'}</td>
            <td>${alert.dst_ip || 'N/A'}</td>
            <td>${alert.protocol || 'Unknown'}</td>
            <td><button class="btn btn-sm btn-danger" onclick="blockIP('${alert.src_ip || ''}')">Block</button></td>
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

let attackMap;

function initAttackMap() {
    attackMap = L.map('attackMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap'
    }).addTo(attackMap);
    
    // Server location (mock)
    const serverLat = 40.7128;
    const serverLon = -74.0060;
    L.marker([serverLat, serverLon]).addTo(attackMap)
        .bindPopup('Your Server').openPopup();
}

async function updateAttackMap() {
    if (!attackMap) initAttackMap();
    
    // Clear old paths
    attackMap.eachLayer(function (layer) {
        if (layer instanceof L.Polyline) {
            attackMap.removeLayer(layer);
        }
    });

    try {
        const response = await fetch('/api/attack_locations');
        const locations = await response.json();
        
        const serverLat = 40.7128;
        const serverLon = -74.0060;
        
        locations.forEach(loc => {
            const color = loc.type === 'DDoS' ? '#ff3b3b' : '#ffc107';
            
            const antPath = L.antPath(
                [[loc.lat, loc.lon], [serverLat, serverLon]],
                {
                    color: color,
                    weight: 3,
                    opacity: 0.8,
                    delay: 1000,
                    dashArray: [10, 20],
                    pulseColor: color
                }
            ).addTo(attackMap);
            
            L.marker([loc.lat, loc.lon], {
                icon: L.divIcon({
                    className: 'attack-marker',
                    html: `<div style="background:${color};width:12px;height:12px;border-radius:50%;box-shadow:0 0 10px ${color}40"></div>`,
                    iconSize: [12, 12]
                })
            }).addTo(attackMap).bindPopup(`<b>${loc.ip}</b><br/>${loc.type}`);
        });
    } catch (error) {
        console.error('Map error:', error);
    }
}

async function fetchLivePackets() {
    try {
        const response = await fetch('/api/live_packets');
        const packets = await response.json();
        const tbody = document.getElementById('livePacketsTable');
        if (tbody) {
            tbody.innerHTML = '';
            packets.slice(0, 10).forEach(p => {
                const row = tbody.insertRow();
                row.innerHTML = `
                    <td>${new Date(p.time * 1000).toLocaleTimeString()}</td>
                    <td>${p.src_ip}</td>
                    <td>${p.dst_ip}</td>
                    <td>${p.proto}</td>
                    <td>${p.size} B</td>
                `;
            });
        }
    } catch (error) {
        console.error('Live packets error:', error);
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

async function updateAttackChart() {
    try {
        const response = await fetch('/api/attack_timeline');
        const timeline = await response.json();
        
        initChart();
        
        chart.data.labels = timeline.map(t => t.time);
        chart.data.datasets[0].data = timeline.map(t => t.alerts);
        chart.update('active', 500); // Animate
    } catch (error) {
        console.error('Timeline error:', error);
    }
}

// Disabled conflicting blockIP - HTML has inline blockIP using /api/block/${ip}

let trafficChart = null;
let trafficData = [];

function initTrafficChart() {
    const ctx = document.getElementById('trafficChart')?.getContext('2d');
    if (!ctx) return;
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'PPS',
                data: [],
                borderColor: '#00e5ff',
                backgroundColor: 'rgba(0,229,255,0.2)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            scales: {
                y: { display: false, beginAtZero: true, max: 2000 }
            },
            plugins: { legend: { display: false } },
            interaction: { intersect: false }
        }
    });
}

async function fetchNetworkTraffic() {
    try {
        const response = await fetch('/api/network_traffic');
        const data = await response.json();
        const ppsEl = document.getElementById('livePPS');
        if (ppsEl) ppsEl.textContent = data.pps.toLocaleString();
        
        if (trafficChart) {
            trafficData.push(data.pps);
            if (trafficData.length > 30) trafficData.shift();
            trafficChart.data.labels = Array.from({length: trafficData.length}, (_, i) => i);
            trafficChart.data.datasets[0].data = trafficData;
            trafficChart.update('none');
        }
    } catch (error) {
        console.error('Network traffic error:', error);
    }
}

function updateLiveMetrics() {
    fetchNetworkTraffic();
}

// JS disabled - HTML script is self-contained and auto-refreshes
