document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const uploadStatus = document.getElementById('upload-status');
    const statusText = document.getElementById('status-text');
    const analysisResult = document.getElementById('analysis-result');
    const detectedLanguage = document.getElementById('detected-language');
    const filename = document.getElementById('filename');
    const sourceCode = document.getElementById('source-code');
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    const highCount = document.getElementById('high-count');
    const mediumCount = document.getElementById('medium-count');
    const lowCount = document.getElementById('low-count');
    const highCountText = document.getElementById('high-count-text');
    const mediumCountText = document.getElementById('medium-count-text');
    const lowCountText = document.getElementById('low-count-text');
    const languageIcon = document.getElementById('language-icon');
    const themeToggle = document.getElementById('theme-toggle');
    const codeTheme = document.getElementById('code-theme');
    const copyCodeBtn = document.getElementById('copy-code');

    // Language icons mapping
    const languageIcons = {
        'Python': 'https://upload.wikimedia.org/wikipedia/commons/c/c3/Python-logo-notext.svg',
        'JavaScript': 'https://upload.wikimedia.org/wikipedia/commons/6/6a/JavaScript-logo.png',
        'Java': 'https://upload.wikimedia.org/wikipedia/en/3/30/Java_programming_language_logo.svg',
        'C': 'https://upload.wikimedia.org/wikipedia/commons/3/35/The_C_Programming_Language_logo.svg',
        'C++': 'https://upload.wikimedia.org/wikipedia/commons/1/18/ISO_C%2B%2B_Logo.svg',
        'PHP': 'https://upload.wikimedia.org/wikipedia/commons/2/27/PHP-logo.svg',
        'Ruby': 'https://upload.wikimedia.org/wikipedia/commons/7/73/Ruby_logo.svg',
        'Go': 'https://upload.wikimedia.org/wikipedia/commons/0/05/Go_Logo_Blue.svg'
    };

    // Theme toggle function
    themeToggle.addEventListener('change', function() {
        if (themeToggle.checked) {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
            codeTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/atom-one-dark.min.css';
        } else {
            document.documentElement.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
            codeTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/atom-one-light.min.css';
        }
    });

    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        themeToggle.checked = true;
        document.documentElement.setAttribute('data-theme', 'dark');
        codeTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/atom-one-dark.min.css';
    } else if (savedTheme === 'light') {
        codeTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/atom-one-light.min.css';
    }

    // Copy code button
    copyCodeBtn.addEventListener('click', function() {
        const codeText = sourceCode.textContent;
        navigator.clipboard.writeText(codeText).then(() => {
            const originalText = copyCodeBtn.innerHTML;
            copyCodeBtn.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
            setTimeout(() => {
                copyCodeBtn.innerHTML = originalText;
            }, 2000);
        });
    });

    // Add drag and drop events
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadArea.classList.add('highlight');
    });

    uploadArea.addEventListener('dragleave', function() {
        uploadArea.classList.remove('highlight');
    });

    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('highlight');
        
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });

    fileInput.addEventListener('change', function() {
        if (fileInput.files.length) {
            handleFile(fileInput.files[0]);
        }
    });

    // Handle file upload
    function handleFile(file) {
        // Show upload status
        uploadStatus.classList.remove('d-none');
        statusText.textContent = 'Analyzing your code...';
        
        // Create FormData
        const formData = new FormData();
        formData.append('file', file);
        
        // Send file to backend
        fetch('http://localhost:5000/api/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Hide upload status
            uploadStatus.classList.add('d-none');
            
            // Process and display results
            displayResults(data, file.name);
            
            // Scroll to results with smooth animation
            analysisResult.scrollIntoView({ behavior: 'smooth', block: 'start' });
        })
        .catch(error => {
            uploadStatus.innerHTML = `
                <div class="alert alert-danger d-flex align-items-center">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    <div>Error: ${error.message}</div>
                </div>`;
            console.error('Error:', error);
        });
    }

    // Display analysis results
    function displayResults(data, fileName) {
        // Show results container
        analysisResult.classList.remove('d-none');
        
        // Set file info
        detectedLanguage.textContent = data.language;
        filename.textContent = fileName;
        
        // Set language icon
        if (languageIcons[data.language]) {
            languageIcon.style.backgroundImage = `url(${languageIcons[data.language]})`;
        }
        
        // Display source code with highlighting
        sourceCode.textContent = data.source_code;
        sourceCode.className = getLanguageClass(data.language);
        hljs.highlightElement(sourceCode);
        
        // Reset vulnerability counts
        let highVulnCount = 0;
        let mediumVulnCount = 0;
        let lowVulnCount = 0;
        
        // Clear previous vulnerabilities
        vulnerabilitiesList.innerHTML = '';
        
        // Add vulnerabilities
        data.vulnerabilities.forEach((vuln, index) => {
            // Count vulnerabilities by severity
            if (vuln.severity === 'high') highVulnCount++;
            else if (vuln.severity === 'medium') mediumVulnCount++;
            else if (vuln.severity === 'low') lowVulnCount++;
            
            // Create vulnerability item
            const vulnItem = document.createElement('div');
            vulnItem.className = `vulnerability-item list-group-item list-group-item-action ${vuln.severity}`;
            vulnItem.dataset.vulnId = index;
            
            vulnItem.innerHTML = `
                <div class="d-flex w-100 justify-content-between align-items-center">
                    <h6 class="mb-1">
                        <span class="severity-indicator severity-${vuln.severity}"></span>
                        ${vuln.name}
                    </h6>
                    <small><i class="fas fa-code me-1"></i>Line: ${vuln.line_number}</small>
                </div>
                <p class="mb-1 text-truncate">${vuln.description}</p>
            `;
            
            // Add click event to show details
            vulnItem.addEventListener('click', function() {
                showVulnerabilityDetails(vuln);
                
                // Highlight the line in code view
                highlightCodeLine(vuln.line_number);
            });
            
            vulnerabilitiesList.appendChild(vulnItem);
        });
        
        // Update vulnerability counts
        highCount.textContent = highVulnCount;
        mediumCount.textContent = mediumVulnCount;
        lowCount.textContent = lowVulnCount;
        highCountText.textContent = highVulnCount;
        mediumCountText.textContent = mediumVulnCount;
        lowCountText.textContent = lowVulnCount;
        
        // Create chart
        createVulnerabilityChart(highVulnCount, mediumVulnCount, lowVulnCount);

        // Add notification if no vulnerabilities found
        if (highVulnCount === 0 && mediumVulnCount === 0 && lowVulnCount === 0) {
            vulnerabilitiesList.innerHTML = `
                <div class="p-4 text-center">
                    <i class="fas fa-check-circle text-success mb-3" style="font-size: 3rem;"></i>
                    <h5>No vulnerabilities detected!</h5>
                    <p class="text-muted">Your code appears to be secure based on our analysis.</p>
                </div>`;
        }
    }

    // Show vulnerability details in modal with improved mobile support
    function showVulnerabilityDetails(vuln) {
        const modal = new bootstrap.Modal(document.getElementById('vulnerabilityModal'));
        const modalTitle = document.getElementById('modal-title');
        const modalContent = document.getElementById('modal-content');
        
        modalTitle.innerHTML = `<i class="fas fa-bug me-2"></i>${vuln.name}`;
        
        // Improved modal content layout for mobile
        modalContent.innerHTML = `
            <div class="alert alert-${getSeverityClass(vuln.severity)} d-flex align-items-center">
                <span class="severity-indicator severity-${vuln.severity} me-2"></span>
                <div>Severity: ${vuln.severity.toUpperCase()}</div>
            </div>
            
            <h6 class="mt-3"><i class="fas fa-info-circle me-2"></i>Description</h6>
            <p>${vuln.description}</p>
            
            <h6 class="mt-3"><i class="fas fa-code me-2"></i>Affected Code (Line ${vuln.line_number})</h6>
            <div class="overflow-auto">
                <pre><code class="p-3 rounded">${escapeHtml(vuln.code_snippet)}</code></pre>
            </div>
            
            <h6 class="mt-3"><i class="fas fa-exclamation-triangle me-2"></i>Impact</h6>
            <p>${vuln.impact}</p>
            
            <h6 class="mt-3"><i class="fas fa-shield-alt me-2"></i>Recommendation</h6>
            <p>${vuln.recommendation}</p>
            
            <h6 class="mt-3"><i class="fas fa-external-link-alt me-2"></i>References</h6>
            <ul>
                ${vuln.references.map(ref => `<li><a href="${ref.url}" target="_blank" class="word-break">${ref.title}</a></li>`).join('')}
            </ul>
        `;
        
        // Highlight code in modal
        const codeElements = modalContent.querySelectorAll('code');
        codeElements.forEach(el => {
            hljs.highlightElement(el);
        });
        
        modal.show();
    }

    // Highlight code line with improved mobile experience
    function highlightCodeLine(lineNumber) {
        // Remove previous highlighting
        const highlighted = sourceCode.querySelectorAll('.highlighted-line');
        highlighted.forEach(el => el.classList.remove('highlighted-line'));
        
        // Get line elements
        const codeLines = sourceCode.innerText.split('\n');
        
        // Replace code display with line numbers and highlighting
        let codeWithLines = '';
        codeLines.forEach((line, index) => {
            const lineNum = index + 1;
            const isHighlighted = lineNum === parseInt(lineNumber);
            const highlightClass = isHighlighted ? 'highlighted-line' : '';
            
            codeWithLines += `<span class="${highlightClass}"><span class="code-line-number">${lineNum}</span>${line}</span>\n`;
        });
        
        sourceCode.innerHTML = codeWithLines;
        
        // Scroll to highlighted line with better mobile support
        const highlightedLine = sourceCode.querySelector('.highlighted-line');
        if (highlightedLine) {
            // Use smaller offset on mobile
            const isMobile = window.innerWidth < 768;
            const scrollOptions = {
                behavior: 'smooth',
                block: isMobile ? 'start' : 'center'
            };
            
            setTimeout(() => {
                highlightedLine.scrollIntoView(scrollOptions);
            }, 100);
        }
    }

    // Create vulnerability chart with improved responsiveness
    function createVulnerabilityChart(high, medium, low) {
        const ctx = document.getElementById('vulnerabilities-chart').getContext('2d');
        
        // Destroy previous chart if it exists
        if (window.vulnerabilityChart) {
            window.vulnerabilityChart.destroy();
        }
        
        // Get theme colors
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const textColor = isDark ? '#e9ecef' : '#343a40';
        
        // Check if we're on a mobile device
        const isMobile = window.innerWidth < 768;
        
        window.vulnerabilityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [high, medium, low],
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(23, 162, 184, 0.8)'
                    ],
                    borderColor: [
                        'rgba(220, 53, 69, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(23, 162, 184, 1)'
                    ],
                    borderWidth: 1,
                    borderRadius: 5
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: isDark ? '#343a40' : '#ffffff',
                        titleColor: textColor,
                        bodyColor: textColor,
                        borderColor: isDark ? '#6c757d' : '#e9ecef',
                        borderWidth: 1,
                        padding: isMobile ? 8 : 10,
                        displayColors: false,
                        callbacks: {
                            label: function(context) {
                                return `${context.raw} vulnerability${context.raw !== 1 ? 'ies' : 'y'} found`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: textColor,
                            font: {
                                size: isMobile ? 10 : 12
                            }
                        },
                        grid: {
                            color: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: textColor,
                            font: {
                                size: isMobile ? 10 : 12
                            }
                        },
                        grid: {
                            display: false
                        }
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart'
                }
            }
        });
    }

    // Handle window resize for responsive behavior
    window.addEventListener('resize', function() {
        const highCount = parseInt(highCountText.textContent);
        const mediumCount = parseInt(mediumCountText.textContent);
        const lowCount = parseInt(lowCountText.textContent);
        
        if (highCount > 0 || mediumCount > 0 || lowCount > 0) {
            createVulnerabilityChart(highCount, mediumCount, lowCount);
        }
    });

    // Helper functions
    function getLanguageClass(language) {
        const languageMap = {
            'Python': 'language-python',
            'JavaScript': 'language-javascript',
            'Java': 'language-java',
            'C': 'language-c',
            'C++': 'language-cpp',
            'PHP': 'language-php',
            'Ruby': 'language-ruby',
            'Go': 'language-go'
        };
        
        return languageMap[language] || 'language-plaintext';
    }

    function getSeverityClass(severity) {
        const severityMap = {
            'high': 'danger',
            'medium': 'warning',
            'low': 'info'
        };
        
        return severityMap[severity] || 'secondary';
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Update chart colors when theme changes
    themeToggle.addEventListener('change', function() {
        const highCount = parseInt(highCountText.textContent);
        const mediumCount = parseInt(mediumCountText.textContent);
        const lowCount = parseInt(lowCountText.textContent);
        
        if (highCount > 0 || mediumCount > 0 || lowCount > 0) {
            createVulnerabilityChart(highCount, mediumCount, lowCount);
        }
    });
});