// Dashboard JavaScript
let dashboardData = null;

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardData();
    
    // Auto-refresh every 30 seconds
    setInterval(loadDashboardData, 30000);
});

// Load dashboard data from API
async function loadDashboardData() {
    showLoading(true);
    
    try {
        const response = await fetch('/api/dashboard/stats');
        if (!response.ok) throw new Error('Failed to load dashboard data');
        
        dashboardData = await response.json();
        updateDashboard(dashboardData);
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showNotification('Failed to load dashboard data', 'error');
    } finally {
        showLoading(false);
    }
}

// Update dashboard with new data
function updateDashboard(data) {
    updateStatistics(data.statistics);
    updateCharts(data.statistics);
    updateRecentScans(data.recent_scans);
    updateModelPerformance(data.model_performance);
}

// Update statistics cards
function updateStatistics(stats) {
    document.getElementById('total-scans').textContent = stats.total_scans.toLocaleString();
    document.getElementById('malicious-count').textContent = stats.malicious_count.toLocaleString();
    document.getElementById('benign-count').textContent = stats.benign_count.toLocaleString();
    document.getElementById('malicious-percentage').textContent = stats.malicious_percentage.toFixed(1) + '%';
    
    // Animate counters
    animateCounter('total-scans', stats.total_scans);
    animateCounter('malicious-count', stats.malicious_count);
    animateCounter('benign-count', stats.benign_count);
    animateCounter('malicious-percentage', stats.malicious_percentage, '%');
}

// Animate counter values
function animateCounter(elementId, targetValue, suffix = '') {
    const element = document.getElementById(elementId);
    const startValue = 0;
    const duration = 2000;
    const startTime = performance.now();
    
    function updateCounter(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const currentValue = startValue + (targetValue - startValue) * easeOutCubic(progress);
        
        if (suffix === '%') {
            element.textContent = currentValue.toFixed(1) + suffix;
        } else {
            element.textContent = Math.floor(currentValue).toLocaleString() + suffix;
        }
        
        if (progress < 1) {
            requestAnimationFrame(updateCounter);
        }
    }
    
    requestAnimationFrame(updateCounter);
}

// Easing function
function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
}

// Update charts
function updateCharts(stats) {
    updatePieChart(stats);
    updateBarChart(stats);
    updateLineChart(stats);
}

// Update pie chart
function updatePieChart(stats) {
    const data = [{
        values: [stats.benign_count, stats.malicious_count],
        labels: ['Benign', 'Malicious'],
        type: 'pie',
        marker: {
            colors: ['#22c55e', '#ef4444'],
            line: { color: '#1a2332', width: 2 }
        },
        textinfo: 'label+percent',
        textposition: 'outside',
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    }];
    
    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#e6edf3' },
        showlegend: false,
        margin: { t: 20, b: 20, l: 20, r: 20 }
    };
    
    Plotly.newPlot('pie-chart', data, layout, {responsive: true, displayModeBar: false});
}

// Update bar chart
function updateBarChart(stats) {
    const algorithms = Object.keys(stats.algorithm_usage);
    const counts = Object.values(stats.algorithm_usage);
    
    const data = [{
        x: algorithms,
        y: counts,
        type: 'bar',
        marker: {
            color: '#0ea5e9',
            line: { color: '#0284c7', width: 1 }
        },
        hovertemplate: '<b>%{x}</b><br>Scans: %{y}<extra></extra>'
    }];
    
    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#e6edf3' },
        margin: { t: 20, b: 40, l: 40, r: 20 },
        xaxis: { 
            gridcolor: 'rgba(255,255,255,0.1)',
            linecolor: 'rgba(255,255,255,0.2)'
        },
        yaxis: { 
            gridcolor: 'rgba(255,255,255,0.1)',
            linecolor: 'rgba(255,255,255,0.2)'
        }
    };
    
    Plotly.newPlot('bar-chart', data, layout, {responsive: true, displayModeBar: false});
}

// Update line chart
function updateLineChart(stats) {
    const dailyData = stats.daily_scans || [];
    const dates = dailyData.map(d => d.date);
    const counts = dailyData.map(d => d.count);
    
    const data = [{
        x: dates,
        y: counts,
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: '#0ea5e9', width: 3 },
        marker: { color: '#0ea5e9', size: 6 },
        hovertemplate: '<b>%{x}</b><br>Scans: %{y}<extra></extra>'
    }];
    
    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#e6edf3' },
        margin: { t: 20, b: 40, l: 40, r: 20 },
        xaxis: { 
            gridcolor: 'rgba(255,255,255,0.1)',
            linecolor: 'rgba(255,255,255,0.2)'
        },
        yaxis: { 
            gridcolor: 'rgba(255,255,255,0.1)',
            linecolor: 'rgba(255,255,255,0.2)'
        }
    };
    
    Plotly.newPlot('line-chart', data, layout, {responsive: true, displayModeBar: false});
}

// Update recent scans table
function updateRecentScans(scans) {
    const tbody = document.getElementById('recent-scans-table');
    tbody.innerHTML = '';
    
    scans.forEach(scan => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatDateTime(scan.scan_timestamp)}</td>
            <td>${truncateText(scan.filename, 30)}</td>
            <td><span class="algorithm-badge">${scan.algorithm.toUpperCase()}</span></td>
            <td><span class="status-badge status-${scan.label}">${scan.label}</span></td>
            <td>${(scan.confidence * 100).toFixed(1)}%</td>
            <td>${formatBytes(scan.file_size)}</td>
            <td>
                <button class="btn btn-small" onclick="viewScanDetails(${scan.id})">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Update model performance
function updateModelPerformance(performance) {
    const grid = document.getElementById('model-performance-grid');
    grid.innerHTML = '';
    
    performance.forEach(model => {
        const card = document.createElement('div');
        card.className = 'performance-card';
        card.innerHTML = `
            <h4>${model.algorithm.toUpperCase()}</h4>
            <div class="performance-metric">${(model.accuracy * 100).toFixed(1)}%</div>
            <div class="performance-label">Accuracy</div>
            <div style="margin-top: 0.5rem; font-size: 0.75rem; color: #94a3b8;">
                <div>Precision: ${(model.precision * 100).toFixed(1)}%</div>
                <div>Recall: ${(model.recall * 100).toFixed(1)}%</div>
                <div>F1: ${(model.f1_score * 100).toFixed(1)}%</div>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Utility functions
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function showLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (show) {
        overlay.classList.add('show');
    } else {
        overlay.classList.remove('show');
    }
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(14, 165, 233, 0.9)'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        z-index: 10000;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        animation: slideInRight 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// Event handlers
function refreshDashboard() {
    loadDashboardData();
    showNotification('Dashboard refreshed', 'info');
}

function exportData() {
    if (!dashboardData) {
        showNotification('No data available to export', 'error');
        return;
    }
    
    const csvContent = generateCSV(dashboardData);
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maldetect-dashboard-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showNotification('Data exported successfully', 'info');
}

function generateCSV(data) {
    const headers = ['Timestamp', 'Filename', 'Algorithm', 'Result', 'Confidence', 'Size', 'SHA256'];
    const rows = data.recent_scans.map(scan => [
        scan.scan_timestamp,
        scan.filename,
        scan.algorithm,
        scan.label,
        scan.confidence,
        scan.file_size,
        scan.sha256
    ]);
    
    return [headers, ...rows].map(row => 
        row.map(field => `"${field}"`).join(',')
    ).join('\n');
}

function viewScanDetails(scanId) {
    // Navigate to scan details page or show modal
    window.location.href = `/scan-details/${scanId}`;
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .algorithm-badge {
        background: rgba(14, 165, 233, 0.2);
        color: #0ea5e9;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .btn-small {
        padding: 0.5rem;
        font-size: 0.875rem;
        min-width: auto;
    }
`;
document.head.appendChild(style);
