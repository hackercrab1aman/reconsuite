// Main JavaScript for ReconSuite

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Scan form validation
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            const targetInput = document.getElementById('targetInput');
            
            if (!targetInput.value.trim()) {
                event.preventDefault();
                showAlert('Please enter a valid domain or IP address', 'danger');
                return false;
            }
            
            // Check if at least one scan option is selected
            const checkboxes = document.querySelectorAll('input[type=checkbox]');
            let atLeastOneChecked = false;
            
            checkboxes.forEach(function(checkbox) {
                if (checkbox.checked) {
                    atLeastOneChecked = true;
                }
            });
            
            if (!atLeastOneChecked) {
                event.preventDefault();
                showAlert('Please select at least one scan option', 'danger');
                return false;
            }
            
            showAlert('Starting scan...', 'info');
        });
    }

    // Handle scan execution on results page
    const runScanBtn = document.getElementById('runScanBtn');
    if (runScanBtn) {
        runScanBtn.addEventListener('click', function() {
            startScan();
        });

        // Auto-start scan when results page loads
        startScan();
    }

    // Export results button
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            exportResults();
        });
    }

    // Toggle all checkboxes
    const toggleAllBtn = document.getElementById('toggleAllBtn');
    if (toggleAllBtn) {
        toggleAllBtn.addEventListener('click', function() {
            const checkboxes = document.querySelectorAll('input[type=checkbox]');
            const allChecked = Array.from(checkboxes).every(cb => cb.checked);
            
            checkboxes.forEach(function(checkbox) {
                checkbox.checked = !allChecked;
            });
            
            toggleAllBtn.textContent = allChecked ? 'Select All' : 'Deselect All';
        });
    }
});

// Function to show bootstrap alerts
function showAlert(message, type = 'success') {
    const alertsContainer = document.getElementById('alerts');
    if (!alertsContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.role = 'alert';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertsContainer.appendChild(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    }, 5000);
}

// Start the scan process
function startScan() {
    const scanContainer = document.getElementById('scanContainer');
    const progressBar = document.getElementById('scanProgress');
    const progressText = document.getElementById('progressText');
    const runScanBtn = document.getElementById('runScanBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    
    if (!scanContainer || !progressBar || !progressText) return;
    
    // Update UI to show scan is in progress
    scanContainer.style.display = 'block';
    resultsContainer.style.display = 'none';
    progressBar.style.width = '0%';
    progressText.textContent = 'Initializing scan...';
    
    if (runScanBtn) {
        runScanBtn.disabled = true;
        runScanBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
    }
    
    // Make API call to start scan
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Scan completed successfully
        progressBar.style.width = '100%';
        progressText.textContent = 'Scan completed';
        
        if (runScanBtn) {
            runScanBtn.disabled = false;
            runScanBtn.innerHTML = 'Run Scan Again';
        }
        
        // Process and display results
        displayResults(data);
        
        // Show results container
        setTimeout(() => {
            scanContainer.style.display = 'none';
            resultsContainer.style.display = 'block';
        }, 1000);
    })
    .catch(error => {
        console.error('Error:', error);
        progressBar.style.width = '100%';
        progressBar.className = 'progress-bar bg-danger';
        progressText.textContent = 'Scan failed: ' + error.message;
        
        if (runScanBtn) {
            runScanBtn.disabled = false;
            runScanBtn.innerHTML = 'Try Again';
        }
        
        showAlert('Scan failed: ' + error.message, 'danger');
    });
    
    // Simulate progress for better UX
    simulateProgress();
}

// Simulate progress updates while scanning
function simulateProgress() {
    const progressBar = document.getElementById('scanProgress');
    const progressText = document.getElementById('progressText');
    
    if (!progressBar || !progressText) return;
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress >= 90) {
            progress = 90;
            clearInterval(interval);
        }
        
        progressBar.style.width = progress + '%';
        progressText.textContent = 'Scanning... ' + Math.round(progress) + '%';
    }, 1000);
}

// Display scan results
function displayResults(data) {
    const resultsContainer = document.getElementById('resultsContainer');
    if (!resultsContainer) return;
    
    // Enable export button
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.disabled = false;
    }
    
    // Update result sections if they exist
    updateDnsResults(data.results.dns_recon);
    updateWhoisResults(data.results.whois_lookup);
    updateSubdomainResults(data.results.subdomain_enum);
    updatePortScanResults(data.results.port_scan);
    updateDirectoryResults(data.results.directory_discovery);
    updateVulnerabilityResults(data.results.vulnerability_scan);
    updateHeaderResults(data.results.header_analysis);
    updateTechResults(data.results.tech_detection);
    
    // Initialize any charts
    initCharts(data.results);
    
    // Show the results
    resultsContainer.style.display = 'block';
    
    // Scroll to results
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
}

// Update DNS recon results
function updateDnsResults(data) {
    const container = document.getElementById('dnsReconResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Create table for DNS records
    html += '<table class="table table-sm table-striped">';
    html += '<thead><tr><th>Record Type</th><th>Value</th></tr></thead>';
    html += '<tbody>';
    
    // Add each record type
    for (const [recordType, records] of Object.entries(data)) {
        if (recordType === 'has_dnssec') continue;
        
        if (Array.isArray(records)) {
            records.forEach(record => {
                html += `<tr><td>${recordType}</td><td>${record}</td></tr>`;
            });
        }
    }
    
    html += '</tbody></table>';
    
    // Add DNSSEC info
    const dnssec = data.has_dnssec ? 
        '<span class="badge bg-success">Enabled</span>' : 
        '<span class="badge bg-warning">Not Enabled</span>';
    
    html += `<p><strong>DNSSEC:</strong> ${dnssec}</p>`;
    html += '</div>';
    
    container.innerHTML = html;
}

// Update WHOIS results
function updateWhoisResults(data) {
    const container = document.getElementById('whoisResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Domain information
    html += `<h5>Domain Information</h5>`;
    html += `<p><strong>Domain:</strong> ${data.domain_name || 'N/A'}</p>`;
    html += `<p><strong>Registrar:</strong> ${data.registrar || 'N/A'}</p>`;
    
    // Dates
    html += `<h5>Important Dates</h5>`;
    html += `<p><strong>Created:</strong> ${data.creation_date || 'N/A'}</p>`;
    html += `<p><strong>Expires:</strong> ${data.expiration_date || 'N/A'}</p>`;
    html += `<p><strong>Updated:</strong> ${data.updated_date || 'N/A'}</p>`;
    
    // Domain age
    if (data.domain_age_days) {
        html += `<p><strong>Domain Age:</strong> ${data.domain_age_days} days</p>`;
    }
    
    // Nameservers
    if (data.name_servers && data.name_servers.length > 0) {
        html += `<h5>Nameservers</h5><ul>`;
        data.name_servers.forEach(ns => {
            html += `<li>${ns}</li>`;
        });
        html += `</ul>`;
    }
    
    // Status
    if (data.status && data.status.length > 0) {
        html += `<h5>Domain Status</h5><ul>`;
        data.status.forEach(status => {
            html += `<li>${status}</li>`;
        });
        html += `</ul>`;
    }
    
    // Contact emails
    if (data.emails && data.emails.length > 0) {
        html += `<h5>Contact Emails</h5><ul>`;
        data.emails.forEach(email => {
            html += `<li>${email}</li>`;
        });
        html += `</ul>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Update subdomain results
function updateSubdomainResults(data) {
    const container = document.getElementById('subdomainResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Summary
    html += `<p><strong>Domain:</strong> ${data.domain}</p>`;
    html += `<p><strong>Total Subdomains Found:</strong> ${data.total_found}</p>`;
    
    // Subdomains list
    if (data.subdomains && data.subdomains.length > 0) {
        html += `<h5>Discovered Subdomains</h5>`;
        html += `<div class="table-responsive">`;
        html += `<table class="table table-sm table-hover">`;
        html += `<thead><tr><th>Subdomain</th><th>Actions</th></tr></thead>`;
        html += `<tbody>`;
        
        data.subdomains.forEach(subdomain => {
            html += `<tr>
                <td>${subdomain}</td>
                <td>
                    <a href="http://${subdomain}" target="_blank" class="btn btn-sm btn-outline-primary">
                        <i class="fa fa-external-link"></i> Visit
                    </a>
                </td>
            </tr>`;
        });
        
        html += `</tbody></table></div>`;
    } else {
        html += `<div class="alert alert-info">No subdomains discovered</div>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Update port scan results
function updatePortScanResults(data) {
    const container = document.getElementById('portScanResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Summary
    html += `<p><strong>Target:</strong> ${data.target} (${data.ip})</p>`;
    html += `<p><strong>Open Ports:</strong> ${data.total_open_ports}</p>`;
    
    // Open ports table
    if (data.ports && data.ports.length > 0) {
        html += `<h5>Open Ports</h5>`;
        html += `<div class="table-responsive">`;
        html += `<table class="table table-sm table-hover">`;
        html += `<thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Status</th></tr></thead>`;
        html += `<tbody>`;
        
        data.ports.forEach(port => {
            html += `<tr>
                <td>${port.port}</td>
                <td>${port.service || 'unknown'}</td>
                <td>${port.version || 'N/A'}</td>
                <td><span class="badge bg-success">${port.status}</span></td>
            </tr>`;
        });
        
        html += `</tbody></table></div>`;
    } else {
        html += `<div class="alert alert-info">No open ports discovered</div>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Update directory discovery results
function updateDirectoryResults(data) {
    const container = document.getElementById('directoryResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Summary
    html += `<p><strong>Target:</strong> ${data.target}</p>`;
    html += `<p><strong>Paths Found:</strong> ${data.total_found}</p>`;
    
    // Discovered paths table
    if (data.paths && data.paths.length > 0) {
        html += `<h5>Discovered Paths</h5>`;
        html += `<div class="table-responsive">`;
        html += `<table class="table table-sm table-hover">`;
        html += `<thead><tr><th>URL</th><th>Status</th><th>Size (bytes)</th><th>Content Type</th></tr></thead>`;
        html += `<tbody>`;
        
        data.paths.forEach(path => {
            // Determine status color
            let statusClass = 'bg-success';
            if (path.status >= 400) {
                statusClass = 'bg-danger';
            } else if (path.status >= 300) {
                statusClass = 'bg-warning';
            }
            
            html += `<tr>
                <td><a href="${path.url}" target="_blank">${path.url}</a></td>
                <td><span class="badge ${statusClass}">${path.status}</span></td>
                <td>${path.size}</td>
                <td>${path.type}</td>
            </tr>`;
        });
        
        html += `</tbody></table></div>`;
    } else {
        html += `<div class="alert alert-info">No paths discovered</div>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Update vulnerability scan results
function updateVulnerabilityResults(data) {
    const container = document.getElementById('vulnerabilityResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Summary
    html += `<p><strong>Target:</strong> ${data.target}</p>`;
    html += `<p><strong>Pages Scanned:</strong> ${data.pages_scanned}</p>`;
    html += `<p><strong>Forms Analyzed:</strong> ${data.forms_analyzed}</p>`;
    html += `<p><strong>Vulnerabilities Found:</strong> ${data.total_vulnerabilities}</p>`;
    
    // Vulnerabilities table
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        html += `<h5>Discovered Vulnerabilities</h5>`;
        
        data.vulnerabilities.forEach((vuln, index) => {
            // Determine severity class
            let severityClass = 'severity-medium';
            if (vuln.type === 'XSS' || vuln.type === 'SQL Injection') {
                severityClass = 'severity-high';
            } else if (vuln.type === 'LFI') {
                severityClass = 'severity-high';
            }
            
            html += `<div class="vuln-report">
                <h6 class="${severityClass}">${vuln.type} Vulnerability</h6>
                <p><strong>URL:</strong> ${vuln.url}</p>
                <p><strong>Method:</strong> ${vuln.method.toUpperCase()}</p>
                <p><strong>Parameter:</strong> ${vuln.param}</p>
                <p><strong>Description:</strong> ${vuln.description}</p>
                <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
            </div>`;
        });
    } else {
        html += `<div class="alert alert-success">No vulnerabilities discovered!</div>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Update HTTP header analysis results
function updateHeaderResults(data) {
    const container = document.getElementById('headerResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Security score
    html += `<div class="row mb-4">
        <div class="col-md-4">
            <div class="score-gauge">
                <canvas id="securityScoreGauge" width="120" height="120"></canvas>
                <div class="score-value">${data.security_score}</div>
            </div>
        </div>
        <div class="col-md-8">
            <h5>Security Score: ${data.security_score}/100</h5>
            <p>Based on HTTP security headers implementation</p>
            <p><strong>Issues Found:</strong> ${data.total_issues}</p>
        </div>
    </div>`;
    
    // Headers found
    if (Object.keys(data.headers_found).length > 0) {
        html += `<h5>Implemented Headers</h5>`;
        html += `<div class="table-responsive">`;
        html += `<table class="table table-sm">`;
        html += `<thead><tr><th>Header</th><th>Value</th></tr></thead>`;
        html += `<tbody>`;
        
        for (const [header, value] of Object.entries(data.headers_found)) {
            html += `<tr>
                <td>${header}</td>
                <td><code>${value}</code></td>
            </tr>`;
        }
        
        html += `</tbody></table></div>`;
    }
    
    // Missing headers
    if (data.missing_headers && data.missing_headers.length > 0) {
        html += `<h5>Missing Security Headers</h5>`;
        html += `<ul class="list-group">`;
        
        data.missing_headers.forEach(header => {
            html += `<li class="list-group-item list-group-item-warning">${header}</li>`;
        });
        
        html += `</ul>`;
    }
    
    // Security issues
    if (data.issues && data.issues.length > 0) {
        html += `<h5 class="mt-4">Security Issues</h5>`;
        
        data.issues.forEach(issue => {
            let severityClass = 'bg-info';
            if (issue.severity === 'High') {
                severityClass = 'bg-danger';
            } else if (issue.severity === 'Medium') {
                severityClass = 'bg-warning';
            }
            
            html += `<div class="card mb-3 border-${severityClass.replace('bg-', '')}">
                <div class="card-header ${severityClass} text-white">
                    ${issue.header} - ${issue.severity} Severity
                </div>
                <div class="card-body">
                    <p><strong>Value:</strong> ${issue.value}</p>
                    <p>${issue.description}</p>
                </div>
            </div>`;
        });
    }
    
    html += '</div>';
    container.innerHTML = html;
    
    // Initialize security score gauge
    initSecurityScoreGauge(data.security_score);
}

// Update technology detection results
function updateTechResults(data) {
    const container = document.getElementById('techResults');
    if (!container || !data) return;
    
    let html = '<div class="card-body">';
    
    // Summary
    html += `<p><strong>Target:</strong> ${data.target}</p>`;
    html += `<p><strong>Technologies Detected:</strong> ${data.total_technologies}</p>`;
    
    // Display categorized technologies
    if (data.categorized && Object.keys(data.categorized).length > 0) {
        for (const [category, techs] of Object.entries(data.categorized)) {
            if (techs.length === 0) continue;
            
            html += `<h5 class="mt-4">${category.charAt(0).toUpperCase() + category.slice(1)}</h5>`;
            html += `<div class="row">`;
            
            techs.forEach(tech => {
                html += `<div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h6 class="card-title">${tech.name.charAt(0).toUpperCase() + tech.name.slice(1)}</h6>
                            <div class="progress mb-2">
                                <div class="progress-bar" role="progressbar" style="width: ${tech.confidence}%" 
                                    aria-valuenow="${tech.confidence}" aria-valuemin="0" aria-valuemax="100">
                                    ${tech.confidence}%
                                </div>
                            </div>
                            <p class="card-text small">Confidence: ${tech.confidence}%</p>
                        </div>
                    </div>
                </div>`;
            });
            
            html += `</div>`;
        }
    } else if (data.technologies && Object.keys(data.technologies).length > 0) {
        // Fallback to non-categorized display
        html += `<h5>Detected Technologies</h5>`;
        html += `<div class="row">`;
        
        for (const [tech, info] of Object.entries(data.technologies)) {
            html += `<div class="col-md-4 mb-3">
                <div class="card h-100">
                    <div class="card-body">
                        <h6 class="card-title">${tech.charAt(0).toUpperCase() + tech.slice(1)}</h6>
                        <div class="progress mb-2">
                            <div class="progress-bar" role="progressbar" style="width: ${info.confidence}%" 
                                aria-valuenow="${info.confidence}" aria-valuemin="0" aria-valuemax="100">
                                ${info.confidence}%
                            </div>
                        </div>
                        <p class="card-text small">Confidence: ${info.confidence}%</p>
                    </div>
                </div>
            </div>`;
        }
        
        html += `</div>`;
    } else {
        html += `<div class="alert alert-info">No technologies detected</div>`;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

// Initialize charts for visualization
function initCharts(results) {
    // Only initialize if Chart.js is available
    if (typeof Chart === 'undefined') return;
    
    // Port distribution chart
    if (results.port_scan && results.port_scan.ports) {
        const ctx = document.getElementById('portDistributionChart');
        if (ctx) {
            const ports = results.port_scan.ports.map(p => p.port);
            const services = results.port_scan.ports.map(p => p.service || 'unknown');
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ports,
                    datasets: [{
                        label: 'Open Ports',
                        data: ports.map(() => 1),
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    },
                    plugins: {
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `Port ${ports[context.dataIndex]}: ${services[context.dataIndex]}`;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    
    // Vulnerability types chart
    if (results.vulnerability_scan && results.vulnerability_scan.vulnerabilities) {
        const ctx = document.getElementById('vulnTypesChart');
        if (ctx) {
            const vulnTypes = {};
            results.vulnerability_scan.vulnerabilities.forEach(v => {
                vulnTypes[v.type] = (vulnTypes[v.type] || 0) + 1;
            });
            
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: Object.keys(vulnTypes),
                    datasets: [{
                        data: Object.values(vulnTypes),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.2)',
                            'rgba(54, 162, 235, 0.2)',
                            'rgba(255, 206, 86, 0.2)',
                            'rgba(75, 192, 192, 0.2)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)'
                        ],
                        borderWidth: 1
                    }]
                }
            });
        }
    }
    
    // Technology categories chart
    if (results.tech_detection && results.tech_detection.categorized) {
        const ctx = document.getElementById('techCategoriesChart');
        if (ctx) {
            const categories = {};
            for (const [category, techs] of Object.entries(results.tech_detection.categorized)) {
                categories[category] = techs.length;
            }
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(categories).map(c => c.charAt(0).toUpperCase() + c.slice(1)),
                    datasets: [{
                        data: Object.values(categories),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.2)',
                            'rgba(54, 162, 235, 0.2)',
                            'rgba(255, 206, 86, 0.2)',
                            'rgba(75, 192, 192, 0.2)',
                            'rgba(153, 102, 255, 0.2)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)'
                        ],
                        borderWidth: 1
                    }]
                }
            });
        }
    }
}

// Initialize security score gauge
function initSecurityScoreGauge(score) {
    const canvas = document.getElementById('securityScoreGauge');
    if (!canvas || typeof Chart === 'undefined') return;
    
    // Determine color based on score
    let color = '#dc3545'; // Danger/red
    if (score >= 80) {
        color = '#28a745'; // Success/green
    } else if (score >= 60) {
        color = '#ffc107'; // Warning/yellow
    } else if (score >= 40) {
        color = '#fd7e14'; // Orange
    }
    
    new Chart(canvas, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [color, '#e9ecef'],
                borderWidth: 0
            }]
        },
        options: {
            cutout: '80%',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                tooltip: {
                    enabled: false
                },
                legend: {
                    display: false
                }
            }
        }
    });
}

// Export results to JSON file
function exportResults() {
    const scanIdElement = document.getElementById('scanId');
    if (!scanIdElement) return;
    
    const scanId = scanIdElement.value;
    
    fetch(`/api/export/${scanId}`)
        .then(response => response.json())
        .then(data => {
            const dataStr = JSON.stringify(data, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const exportFileDefaultName = `recon_${scanId}.json`;
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
        })
        .catch(error => {
            console.error('Error exporting results:', error);
            showAlert('Error exporting results: ' + error.message, 'danger');
        });
}
