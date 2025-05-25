// Charts.js - Visualization functionality for ReconSuite

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tabs for switching between chart types
    const chartTabs = document.querySelectorAll('.chart-tab');
    if (chartTabs.length > 0) {
        chartTabs.forEach(tab => {
            tab.addEventListener('click', function(e) {
                e.preventDefault();
                const target = this.getAttribute('data-bs-target');
                
                // Hide all chart containers
                document.querySelectorAll('.chart-container').forEach(container => {
                    container.style.display = 'none';
                });
                
                // Show the selected chart container
                document.querySelector(target).style.display = 'block';
                
                // Update active tab
                chartTabs.forEach(t => t.classList.remove('active'));
                this.classList.add('active');
            });
        });
        
        // Activate the first tab by default
        chartTabs[0].click();
    }
});

// Create a bar chart for open ports
function createPortBarChart(container, data) {
    if (!container || !data || !data.ports || data.ports.length === 0) return;
    
    const ports = data.ports.map(p => p.port);
    const services = data.ports.map(p => p.service || 'unknown');
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 200;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ports,
            datasets: [{
                label: 'Open Ports',
                data: ports.map(() => 1),
                backgroundColor: 'rgba(75, 192, 192, 0.5)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Open Ports Distribution'
                },
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

// Create a pie chart for vulnerability types
function createVulnerabilityPieChart(container, data) {
    if (!container || !data || !data.vulnerabilities || data.vulnerabilities.length === 0) return;
    
    const vulnTypes = {};
    data.vulnerabilities.forEach(v => {
        vulnTypes[v.type] = (vulnTypes[v.type] || 0) + 1;
    });
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 300;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(vulnTypes),
            datasets: [{
                data: Object.values(vulnTypes),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Vulnerability Types Distribution'
                },
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Create a doughnut chart for technology categories
function createTechnologyDoughnutChart(container, data) {
    if (!container || !data || !data.categorized) return;
    
    const categories = {};
    for (const [category, techs] of Object.entries(data.categorized)) {
        categories[category] = techs.length;
    }
    
    if (Object.keys(categories).length === 0) return;
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 300;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(categories).map(c => c.charAt(0).toUpperCase() + c.slice(1)),
            datasets: [{
                data: Object.values(categories),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)',
                    'rgba(255, 159, 64, 0.7)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Technology Categories'
                },
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Create a radar chart for security headers
function createSecurityHeadersRadarChart(container, data) {
    if (!container || !data) return;
    
    const securityHeaders = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy'
    ];
    
    const headerValues = securityHeaders.map(header => {
        return data.headers_found && data.headers_found[header] ? 1 : 0;
    });
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 300;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: securityHeaders,
            datasets: [{
                label: 'Security Headers',
                data: headerValues,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(54, 162, 235, 1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                r: {
                    angleLines: {
                        display: true
                    },
                    suggestedMin: 0,
                    suggestedMax: 1,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Security Headers Implementation'
                }
            }
        }
    });
}

// Create a horizontal bar chart for HTTP status codes
function createStatusCodeBarChart(container, data) {
    if (!container || !data || !data.paths || data.paths.length === 0) return;
    
    // Count status codes
    const statusCounts = {};
    data.paths.forEach(path => {
        const statusCode = path.status;
        statusCounts[statusCode] = (statusCounts[statusCode] || 0) + 1;
    });
    
    const statusCodes = Object.keys(statusCounts);
    const counts = Object.values(statusCounts);
    
    // Generate colors based on status code
    const backgroundColors = statusCodes.map(code => {
        if (code >= 500) return 'rgba(220, 53, 69, 0.7)'; // Error
        if (code >= 400) return 'rgba(255, 193, 7, 0.7)'; // Client error
        if (code >= 300) return 'rgba(23, 162, 184, 0.7)'; // Redirect
        return 'rgba(40, 167, 69, 0.7)'; // Success
    });
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 300;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: statusCodes,
            datasets: [{
                label: 'HTTP Status Codes',
                data: counts,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                title: {
                    display: true,
                    text: 'HTTP Status Code Distribution'
                }
            }
        }
    });
}

// Create timeline chart for scan progress
function createScanTimelineChart(container, scanEvents) {
    if (!container || !scanEvents || scanEvents.length === 0) return;
    
    const labels = scanEvents.map(event => event.module);
    const durations = scanEvents.map(event => event.duration);
    
    const ctx = document.createElement('canvas');
    ctx.width = 400;
    ctx.height = 200;
    container.appendChild(ctx);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Duration (seconds)',
                data: durations,
                backgroundColor: 'rgba(75, 192, 192, 0.7)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Duration (seconds)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Scan Module'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Scan Time per Module'
                }
            }
        }
    });
}
