document.addEventListener('DOMContentLoaded', () => {
    // --- Element Selection ---
    const mainContent = document.getElementById('main-content');
    const licenseModal = document.getElementById('license-modal');
    const licenseForm = document.getElementById('license-form');
    const licenseInput = document.getElementById('license-input');
    const browseLicenseBtn = document.getElementById('browse-license-btn');
    const licenseFileName = document.getElementById('license-file-name');
    const activateBtn = document.getElementById('activate-btn');
    const licenseError = document.getElementById('license-error');
    
    const apiKeyForm = document.getElementById('api-key-form');
    const apiKeyInput = document.getElementById('api-key-input');
    const apiKeyStatus = document.getElementById('api-key-status');
    const licenseDetailsDiv = document.getElementById('license-details');
    const licenseEmail = document.getElementById('license-email');
    const licenseTier = document.getElementById('license-tier');
    const licenseExpiry = document.getElementById('license-expiry');

    const uploadForm = document.getElementById('upload-form');
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const fileNameDisplay = document.getElementById('file-name-display');
    const scanBtn = document.getElementById('scan-btn');
    const personaSelector = document.getElementById('persona-selector');
    
    const resultsDiv = document.getElementById('results');
    const resultsPlaceholder = document.getElementById('results-placeholder');
    const loadingDiv = document.getElementById('loading');
    const reportContentDiv = document.getElementById('report-content');
    const errorDisplay = document.getElementById('error-display');
    const summaryReportDiv = document.getElementById('summary-report');
    const rawKubescapeCode = document.querySelector('#raw-kubescape pre code');
    const rawTrivyCode = document.querySelector('#raw-trivy pre code');
    const copyBtn = document.getElementById('copy-btn');
    const downloadPdfBtn = document.getElementById('download-pdf-btn');

    const howToUseBtn = document.getElementById('how-to-use-btn');
    const lightbox = document.getElementById('how-to-use-lightbox');
    const closeLightboxBtn = document.getElementById('close-lightbox-btn');

    let selectedFiles = [];
    let selectedPersona = 'risk_analyst'; // Default persona

    // --- Core Application Logic ---
    async function checkStatus() {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const status = await response.json();

            if (status.is_licensed) {
                licenseModal.classList.add('hidden');
                mainContent.classList.remove('hidden');
                
                // Update UI with license details
                licenseEmail.textContent = status.license_details.email || 'N/A';
                licenseTier.textContent = status.license_details.tier || 'N/A';
                licenseExpiry.textContent = status.license_details.expiry || 'N/A';

                // Handle API key state
                if (status.api_key_set) {
                    apiKeyStatus.textContent = "Your OpenAI API key is configured.";
                    apiKeyInput.classList.add('hidden');
                } else {
                    apiKeyStatus.textContent = "Please add your OpenAI API key to enable report generation.";
                    apiKeyInput.classList.remove('hidden');
                }
            } else {
                licenseModal.classList.remove('hidden');
                mainContent.classList.add('hidden');
            }
        } catch (error) {
            console.error("Error checking status:", error);
            showLicenseError("Could not connect to the server. Please ensure the application is running and refresh the page.");
            licenseModal.classList.remove('hidden');
            mainContent.classList.add('hidden');
        }
    }

    // --- License Handling ---
    browseLicenseBtn.addEventListener('click', () => licenseInput.click());
    licenseInput.addEventListener('change', () => {
        if (licenseInput.files.length > 0) {
            licenseFileName.textContent = licenseInput.files[0].name;
            activateBtn.disabled = false;
        } else {
            licenseFileName.textContent = '';
            activateBtn.disabled = true;
        }
    });

    licenseForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (licenseInput.files.length === 0) return;

        const formData = new FormData();
        formData.append('license', licenseInput.files[0]);

        try {
            const response = await fetch('/api/validate_license', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();

            if (result.status === 'valid') {
                await checkStatus(); // Re-check status to unlock the app
            } else {
                showLicenseError(result.error || 'Invalid license provided.');
            }
        } catch (error) {
            showLicenseError('An error occurred during activation.');
        }
    });

    function showLicenseError(message) {
        licenseError.textContent = message;
        licenseError.classList.remove('hidden');
    }
    
    // --- Main App Event Listeners ---
    apiKeyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const key = apiKeyInput.value;
        if (!key) return;

        try {
            const response = await fetch('/api/save_key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: key })
            });
            const result = await response.json();
            if (result.status === 'ok') {
                apiKeyInput.value = '';
                await checkStatus(); // Refresh status
            } else {
                alert('Failed to save API key.');
            }
        } catch (error) {
            alert('An error occurred while saving the key.');
        }
    });

    personaSelector.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') {
            document.querySelectorAll('.persona-btn').forEach(btn => btn.classList.remove('active'));
            e.target.classList.add('active');
            selectedPersona = e.target.dataset.persona;
        }
    });

    browseBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => handleFiles(fileInput.files));
    
    uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.classList.add('drag-over'); });
    uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        handleFiles(e.dataTransfer.files);
    });

    function handleFiles(files) {
        selectedFiles = Array.from(files);
        scanBtn.disabled = selectedFiles.length === 0;
        fileNameDisplay.textContent = selectedFiles.length > 0 ? selectedFiles.map(f => f.name).join(', ') : '';
    }

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (selectedFiles.length === 0) return;

        resultsPlaceholder.classList.add('hidden');
        resultsDiv.classList.remove('hidden');
        loadingDiv.classList.remove('hidden');
        reportContentDiv.classList.add('hidden');
        errorDisplay.classList.add('hidden');

        const formData = new FormData();
        selectedFiles.forEach(file => formData.append('files', file));
        formData.append('persona', selectedPersona);
        formData.append('filenames', JSON.stringify(selectedFiles.map(f => f.name)));

        try {
            const response = await fetch('/scan', { method: 'POST', body: formData });
            const data = await response.json();

            if (!response.ok) { throw new Error(data.error || 'An unknown server error occurred.'); }
            renderReport(data);
        } catch (error) {
            showError(error.message);
        } finally {
            loadingDiv.classList.add('hidden');
        }
    });

    copyBtn.addEventListener('click', () => {
        const reportText = summaryReportDiv.innerText;
        navigator.clipboard.writeText(reportText).then(() => {
            copyBtn.textContent = 'Copied!';
            setTimeout(() => { copyBtn.textContent = 'Copy Report'; }, 2000);
        });
    });

    downloadPdfBtn.addEventListener('click', () => {
        const element = summaryReportDiv;
        const opt = {
            margin:       [0.5, 0.5, 0.5, 0.5],
            filename:     'sapient-k8s-security-report.pdf',
            image:        { type: 'jpeg', quality: 0.98 },
            html2canvas:  { scale: 2, useCORS: true },
            jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
        };
        html2pdf().set(opt).from(element).save();
    });

    // --- Tab Functionality ---
    const controlTabs = document.querySelectorAll('.control-tab-link');
    const controlTabContents = document.querySelectorAll('.control-tab-content');
    controlTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            controlTabs.forEach(item => item.classList.remove('active'));
            tab.classList.add('active');
            const target = document.getElementById(tab.dataset.tab);
            controlTabContents.forEach(content => content.classList.remove('active'));
            target.classList.add('active');
        });
    });
    
    const resultsTabs = document.querySelectorAll('#results .tab-link');
    const resultsTabContents = document.querySelectorAll('#results .tab-content');
    resultsTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            resultsTabs.forEach(item => item.classList.remove('active'));
            tab.classList.add('active');
            const target = document.getElementById(tab.dataset.tab);
            resultsTabContents.forEach(content => content.classList.remove('active'));
            target.classList.add('active');
        });
    });

    // --- Lightbox ---
    howToUseBtn.addEventListener('click', () => lightbox.classList.remove('hidden'));
    closeLightboxBtn.addEventListener('click', () => lightbox.classList.add('hidden'));
    lightbox.addEventListener('click', (e) => {
        if (e.target === lightbox) {
            lightbox.classList.add('hidden');
        }
    });

    // --- Helper Functions ---
    function renderReport(data) {
        reportContentDiv.classList.remove('hidden');
        errorDisplay.classList.add('hidden');

        if (data.report) { 
            summaryReportDiv.innerHTML = marked.parse(data.report); 
        } else { 
            summaryReportDiv.innerHTML = "<p>The AI did not return a report.</p>"; 
        }

        if (data.errors && data.errors.length > 0) { 
            showError(`Tool Errors:\n- ${data.errors.join('\n- ')}`); 
        }

        rawKubescapeCode.textContent = JSON.stringify(data.raw_kubescape, null, 2);
        rawTrivyCode.textContent = JSON.stringify(data.raw_trivy, null, 2);
        
        hljs.highlightAll();
    }
    
    function showError(message) {
        errorDisplay.textContent = message;
        errorDisplay.classList.remove('hidden');
        reportContentDiv.classList.add('hidden');
    }
    
    // --- Initial Load ---
    checkStatus();
});

