// Bulk Scan JavaScript
let selectedFiles = [];
let scanResults = [];
let isScanning = false;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
});

function initializeEventListeners() {
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');
    
    // File input change
    fileInput.addEventListener('change', handleFileSelect);
    
    // Drag and drop events
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    uploadArea.addEventListener('click', () => fileInput.click());
}

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    
    const files = Array.from(e.dataTransfer.files);
    addFiles(files);
}

function handleFileSelect(e) {
    const files = Array.from(e.target.files);
    addFiles(files);
}

function addFiles(files) {
    files.forEach(file => {
        if (!selectedFiles.find(f => f.name === file.name && f.size === file.size)) {
            selectedFiles.push(file);
        }
    });
    
    updateFileList();
    showSelectedFiles();
}

function updateFileList() {
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '';
    
    selectedFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-info">
                <i class="fas fa-file"></i>
                <div class="file-details">
                    <div class="file-name">${escapeHtml(file.name)}</div>
                    <div class="file-size">${formatBytes(file.size)}</div>
                </div>
            </div>
            <button class="btn btn-danger btn-small" onclick="removeFile(${index})">
                <i class="fas fa-times"></i>
            </button>
        `;
        fileList.appendChild(fileItem);
    });
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateFileList();
    
    if (selectedFiles.length === 0) {
        hideSelectedFiles();
    }
}

function clearFiles() {
    selectedFiles = [];
    document.getElementById('fileInput').value = '';
    hideSelectedFiles();
    hideResults();
}

function showSelectedFiles() {
    document.getElementById('selectedFiles').style.display = 'block';
}

function hideSelectedFiles() {
    document.getElementById('selectedFiles').style.display = 'none';
}

async function startBulkScan() {
    if (selectedFiles.length === 0) {
        showError('Please select files to scan');
        return;
    }
    
    if (isScanning) {
        return;
    }
    
    isScanning = true;
    scanResults = [];
    
    const algorithm = document.getElementById('algoSelect').value;
    
    showProgress();
    hideResults();
    hideError();
    
    const startTime = Date.now();
    document.getElementById('scanStartTime').textContent = new Date().toLocaleTimeString();
    
    let processedCount = 0;
    let threatCount = 0;
    
    try {
        for (let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];
            
            // Update progress
            const progress = ((i + 1) / selectedFiles.length) * 100;
            updateProgress(progress, `Scanning ${file.name}...`, i + 1, selectedFiles.length);
            
            try {
                const result = await scanSingleFile(file, algorithm);
                scanResults.push(result);
                
                if (result.label === 'malicious') {
                    threatCount++;
                }
                
            } catch (error) {
                scanResults.push({
                    filename: file.name,
                    error: error.message,
                    label: 'error'
                });
            }
            
            processedCount++;
            
            // Update scan speed
            const elapsed = (Date.now() - startTime) / 1000;
            const speed = processedCount / elapsed;
            document.getElementById('scanSpeed').textContent = speed.toFixed(1);
            document.getElementById('threatCount').textContent = threatCount;
            
            // Small delay to show progress
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        // Scan complete
        updateProgress(100, 'Scan complete!', selectedFiles.length, selectedFiles.length);
        hideProgress();
        showResults();
        
    } catch (error) {
        showError('Bulk scan failed: ' + error.message);
        hideProgress();
    } finally {
        isScanning = false;
    }
}

async function scanSingleFile(file, algorithm) {
    const formData = new FormData();
    formData.append('file', file);
    if (algorithm) {
        formData.append('algo', algorithm);
    }
    
    const response = await fetch('/api/bulk-scan', {
        method: 'POST',
        body: formData
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.error) {
        throw new Error(data.error);
    }
    
    // Return the result for this file
    const fileResult = data.results.find(r => r.filename === file.name);
    if (!fileResult) {
        throw new Error('No result found for file');
    }
    
    return {
        filename: file.name,
        size: file.size,
        ...fileResult
    };
}

function showProgress() {
    document.getElementById('progressSection').style.display = 'block';
}

function hideProgress() {
    setTimeout(() => {
        document.getElementById('progressSection').style.display = 'none';
    }, 2000);
}

function updateProgress(percentage, text, current, total) {
    document.getElementById('progressText').textContent = text;
    document.getElementById('progressCount').textContent = `${current} / ${total}`;
    document.getElementById('progressFill').style.width = `${percentage}%`;
}

function showResults() {
    updateResultsSummary();
    updateResultsTable();
    document.getElementById('resultsSection').style.display = 'block';
}

function hideResults() {
    document.getElementById('resultsSection').style.display = 'none';
}

function updateResultsSummary() {
    const total = scanResults.length;
    const malicious = scanResults.filter(r => r.label === 'malicious').length;
    const benign = scanResults.filter(r => r.label === 'benign').length;
    const threatRate = total > 0 ? (malicious / total) * 100 : 0;
    
    document.getElementById('totalScanned').textContent = total;
    document.getElementById('maliciousFound').textContent = malicious;
    document.getElementById('benignFound').textContent = benign;
    document.getElementById('threatRate').textContent = threatRate.toFixed(1) + '%';
    
    // Animate counters
    animateCounter('totalScanned', total);
    animateCounter('maliciousFound', malicious);
    animateCounter('benignFound', benign);
    animateCounter('threatRate', threatRate, '%');
}

function updateResultsTable() {
    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';
    
    scanResults.forEach(result => {
        const row = document.createElement('tr');
        
        let statusIcon = '';
        let statusBadge = '';
        
        if (result.error) {
            statusIcon = '<i class="fas fa-exclamation-circle" style="color: #6b7280;"></i>';
            statusBadge = '<span class="status-badge status-error">Error</span>';
        } else if (result.label === 'malicious') {
            statusIcon = '<i class="fas fa-exclamation-triangle" style="color: #ef4444;"></i>';
            statusBadge = '<span class="status-badge status-malicious">Malicious</span>';
        } else {
            statusIcon = '<i class="fas fa-check-circle" style="color: #22c55e;"></i>';
            statusBadge = '<span class="status-badge status-benign">Benign</span>';
        }
        
        row.innerHTML = `
            <td>${statusIcon}</td>
            <td>${escapeHtml(result.filename)}</td>
            <td>${formatBytes(result.size)}</td>
            <td>${statusBadge}</td>
            <td>${result.confidence_malicious ? (result.confidence_malicious * 100).toFixed(1) + '%' : '-'}</td>
            <td>${result.algorithm ? result.algorithm.toUpperCase() : '-'}</td>
            <td>
                ${result.error ? 
                    `<button class="btn btn-secondary btn-small" onclick="showErrorDetails('${escapeHtml(result.error)}')">
                        <i class="fas fa-info-circle"></i>
                    </button>` :
                    `<button class="btn btn-secondary btn-small" onclick="viewScanDetails('${result.filename}')">
                        <i class="fas fa-eye"></i>
                    </button>`
                }
            </td>
        `;
        tbody.appendChild(row);
    });
}

function showError(message) {
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorSection').style.display = 'block';
}

function hideError() {
    document.getElementById('errorSection').style.display = 'none';
}

function showErrorDetails(error) {
    showError('Scan Error: ' + error);
}

function viewScanDetails(filename) {
    // Navigate to detailed view or show modal
    alert(`Detailed view for ${filename} - Feature not implemented yet`);
}

function exportResults() {
    if (scanResults.length === 0) {
        showError('No results to export');
        return;
    }
    
    const csvContent = generateResultsCSV();
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maldetect-bulk-scan-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showNotification('Results exported successfully', 'success');
}

function generateResultsCSV() {
    const headers = ['Filename', 'Size', 'Result', 'Confidence', 'Algorithm', 'Error'];
    const rows = scanResults.map(result => [
        result.filename,
        formatBytes(result.size),
        result.label,
        result.confidence_malicious ? (result.confidence_malicious * 100).toFixed(1) + '%' : '',
        result.algorithm || '',
        result.error || ''
    ]);
    
    return [headers, ...rows].map(row => 
        row.map(field => `"${field}"`).join(',')
    ).join('\n');
}

function downloadReport() {
    // Generate a simple HTML report
    const reportContent = generateHTMLReport();
    const blob = new Blob([reportContent], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maldetect-report-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showNotification('Report downloaded successfully', 'success');
}

function generateHTMLReport() {
    const total = scanResults.length;
    const malicious = scanResults.filter(r => r.label === 'malicious').length;
    const benign = scanResults.filter(r => r.label === 'benign').length;
    const errors = scanResults.filter(r => r.error).length;
    const threatRate = total > 0 ? (malicious / total) * 100 : 0;
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>MalDetect Bulk Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
        .summary-card { background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; }
        .malicious { background: #fee2e2; }
        .benign { background: #dcfce7; }
        .error { background: #f3f4f6; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #f9f9f9; }
        .status-malicious { background: #fee2e2; color: #dc2626; }
        .status-benign { background: #dcfce7; color: #16a34a; }
        .status-error { background: #f3f4f6; color: #6b7280; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MalDetect Bulk Scan Report</h1>
        <p>Generated on ${new Date().toLocaleString()}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>${total}</h3>
            <p>Total Files</p>
        </div>
        <div class="summary-card malicious">
            <h3>${malicious}</h3>
            <p>Threats Detected</p>
        </div>
        <div class="summary-card benign">
            <h3>${benign}</h3>
            <p>Clean Files</p>
        </div>
        <div class="summary-card error">
            <h3>${errors}</h3>
            <p>Errors</p>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Result</th>
                <th>Confidence</th>
                <th>Algorithm</th>
                <th>Error</th>
            </tr>
        </thead>
        <tbody>
            ${scanResults.map(result => `
                <tr>
                    <td>${escapeHtml(result.filename)}</td>
                    <td>${formatBytes(result.size)}</td>
                    <td><span class="status-${result.label}">${result.label}</span></td>
                    <td>${result.confidence_malicious ? (result.confidence_malicious * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${result.algorithm || '-'}</td>
                    <td>${result.error || '-'}</td>
                </tr>
            `).join('')}
        </tbody>
    </table>
</body>
</html>`;
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function animateCounter(elementId, targetValue, suffix = '') {
    const element = document.getElementById(elementId);
    const startValue = 0;
    const duration = 1000;
    const startTime = performance.now();
    
    function updateCounter(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const currentValue = startValue + (targetValue - startValue) * easeOutCubic(progress);
        
        if (suffix === '%') {
            element.textContent = currentValue.toFixed(1) + suffix;
        } else {
            element.textContent = Math.floor(currentValue);
        }
        
        if (progress < 1) {
            requestAnimationFrame(updateCounter);
        }
    }
    
    requestAnimationFrame(updateCounter);
}

function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'check-circle'}"></i>
        <span>${message}</span>
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(34, 197, 94, 0.9)'};
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
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 3000);
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
    
    .btn-small {
        padding: 0.5rem;
        font-size: 0.875rem;
        min-width: auto;
    }
`;
document.head.appendChild(style);
