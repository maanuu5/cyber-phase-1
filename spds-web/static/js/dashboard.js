// SPDS Dashboard JavaScript Logic - Vercel Design Edition

let alertChart = null;
const chartDataHistory = {
    labels: [],
    critical: [],
    high: [],
    medium: [],
    low: []
};

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    loadInterfaces();
    fetchDashboardData();

    // Set polling interval (~2s)
    setInterval(fetchDashboardData, 2000);

    // Event Listeners
    document.getElementById('startCaptureBtn').addEventListener('click', startCapture);
    document.getElementById('stopCaptureBtn').addEventListener('click', stopCapture);
    document.getElementById('pcapForm').addEventListener('submit', uploadPcap);
    document.getElementById('clearDbBtn').addEventListener('click', clearDatabase);
    document.getElementById('searchInput').addEventListener('input', filterAlertsTable);
});

// Initialize Chart.js Line Chart
function initChart() {
    const ctx = document.getElementById('alertChart').getContext('2d');
    alertChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Critical',
                    data: [],
                    borderColor: '#ff0055',
                    backgroundColor: 'rgba(255, 0, 85, 0.05)',
                    borderWidth: 1.5,
                    pointRadius: 2,
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'High',
                    data: [],
                    borderColor: '#ff6600',
                    backgroundColor: 'rgba(255, 102, 0, 0.05)',
                    borderWidth: 1.5,
                    pointRadius: 2,
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: [],
                    borderColor: '#f5a623',
                    backgroundColor: 'rgba(245, 166, 35, 0.05)',
                    borderWidth: 1.5,
                    pointRadius: 2,
                    tension: 0.2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#666666', font: { family: 'Inter', size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#666666', precision: 0, font: { family: 'Inter', size: 11 } }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#888888', font: { family: 'Inter', size: 12 } }
                }
            }
        }
    });
}

// Fetch Interfaces
async function loadInterfaces() {
    try {
        const res = await fetch('/api/interfaces');
        const data = await res.json();
        const select = document.getElementById('interfaceSelect');
        select.innerHTML = '';

        if (data.success && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.id;
                opt.textContent = `${iface.name} (${iface.id})`;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = '<option value="default">Default Interface</option>';
        }
    } catch (err) {
        console.error('Error loading interfaces:', err);
    }
}

// Main Polling Data Fetch
async function fetchDashboardData() {
    try {
        const [alertsRes, statsRes] = await Promise.all([
            fetch('/api/alerts?limit=50'),
            fetch('/api/stats')
        ]);

        const alertsData = await alertsRes.json();
        const statsData = await statsRes.json();

        if (alertsData.success) {
            renderAlertsTable(alertsData.alerts);
        }

        if (statsData.success) {
            updateStatsUI(statsData.stats);
        }
    } catch (err) {
        console.error('Error fetching dashboard data:', err);
    }
}

// Update Stats Cards & Chart
function updateStatsUI(stats) {
    document.getElementById('statTotalAlerts').textContent = stats.total_alerts || 0;

    const risk = stats.risk_breakdown || {};
    const criticalHighCount = (risk['Critical'] || 0) + (risk['High'] || 0);
    document.getElementById('statCriticalHigh').textContent = criticalHighCount;
    document.getElementById('statMedium').textContent = risk['Medium'] || 0;

    const topIps = stats.top_source_ips || [];
    if (topIps.length > 0) {
        document.getElementById('statTopIp').textContent = topIps[0].src_ip;
        document.getElementById('statTopIpCount').textContent = `${topIps[0].count} alerts recorded`;
    } else {
        document.getElementById('statTopIp').textContent = 'None';
        document.getElementById('statTopIpCount').textContent = '0 alerts';
    }

    // Live Capture Status Indicator
    const live = stats.live_capture || {};
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    const startBtn = document.getElementById('startCaptureBtn');
    const stopBtn = document.getElementById('stopCaptureBtn');

    if (live.is_running) {
        dot.classList.add('active');
        text.textContent = `Capturing live on ${live.interface} (${live.packet_count} pkts)`;
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        dot.classList.remove('active');
        text.textContent = 'Capture Offline';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }

    // Update Chart History Point
    const nowStr = new Date().toLocaleTimeString();
    if (chartDataHistory.labels.length > 10) {
        chartDataHistory.labels.shift();
        chartDataHistory.critical.shift();
        chartDataHistory.high.shift();
        chartDataHistory.medium.shift();
    }

    chartDataHistory.labels.push(nowStr);
    chartDataHistory.critical.push(risk['Critical'] || 0);
    chartDataHistory.high.push(risk['High'] || 0);
    chartDataHistory.medium.push(risk['Medium'] || 0);

    alertChart.data.labels = chartDataHistory.labels;
    alertChart.data.datasets[0].data = chartDataHistory.critical;
    alertChart.data.datasets[1].data = chartDataHistory.high;
    alertChart.data.datasets[2].data = chartDataHistory.medium;
    alertChart.update();
}

// Render Alerts Table
function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-state">No alerts recorded yet. Start live capture or upload a PCAP file.</td>
            </tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        const riskClass = (a.risk_level || 'low').toLowerCase();
        return `
            <tr>
                <td>${a.id}</td>
                <td>${a.timestamp}</td>
                <td><strong>${escapeHtml(a.alert_type)}</strong></td>
                <td><span class="badge badge-${riskClass}">${escapeHtml(a.risk_level)}</span></td>
                <td>${escapeHtml(a.src_ip)}</td>
                <td>${escapeHtml(a.dst_ip)}</td>
                <td>${escapeHtml(a.details)}</td>
            </tr>`;
    }).join('');

    filterAlertsTable();
}

// Dynamic Filter Function
function filterAlertsTable() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#alertsTableBody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

// Start Capture Action
async function startCapture() {
    const iface = document.getElementById('interfaceSelect').value;
    try {
        const res = await fetch('/api/start_capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface })
        });
        const data = await res.json();
        if (data.success) {
            fetchDashboardData();
        } else {
            alert(`Failed to start capture: ${data.error}`);
        }
    } catch (err) {
        alert(`Error starting capture: ${err.message}`);
    }
}

// Stop Capture Action
async function stopCapture() {
    try {
        const res = await fetch('/api/stop_capture', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            fetchDashboardData();
        } else {
            alert(`Failed to stop capture: ${data.error}`);
        }
    } catch (err) {
        alert(`Error stopping capture: ${err.message}`);
    }
}

// Upload PCAP Action
async function uploadPcap(e) {
    e.preventDefault();
    const fileInput = document.getElementById('pcapFileInput');
    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    const uploadBtn = document.getElementById('uploadPcapBtn');
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Processing PCAP...';

    try {
        const res = await fetch('/api/upload_pcap', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.success) {
            alert(`PCAP Processed Successfully!\nTotal Packets: ${data.total_packets}\nAlerts Detected: ${data.alerts_count}`);
            fileInput.value = '';
            fetchDashboardData();
        } else {
            alert(`PCAP Error: ${data.error}`);
        }
    } catch (err) {
        alert(`Failed to upload PCAP: ${err.message}`);
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Process and Analyze PCAP';
    }
}

// Clear Database Action
async function clearDatabase() {
    if (!confirm('Are you sure you want to clear all recorded alerts from the database?')) return;
    try {
        const res = await fetch('/api/clear_db', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            chartDataHistory.labels = [];
            chartDataHistory.critical = [];
            chartDataHistory.high = [];
            chartDataHistory.medium = [];
            fetchDashboardData();
        }
    } catch (err) {
        alert(`Error clearing database: ${err.message}`);
    }
}

// Utility HTML escaper
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
