document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const selectedFiles = document.getElementById('selectedFiles');
    const totalFiles = document.getElementById('totalFiles');
    const totalSize = document.getElementById('totalSize');
    const password = document.getElementById('password');
    const showPassword = document.getElementById('showPassword');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const progress = document.getElementById('progress');
    const progressBar = progress.querySelector('.progress-bar');
    const progressPercent = document.getElementById('progressPercent');
    const currentFileName = document.getElementById('currentFileName');

    let files = [];

    // Drag and drop functionality
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        dropZone.classList.add('dragover');
    }

    function unhighlight(e) {
        dropZone.classList.remove('dragover');
    }

    // Handle file drop and selection
    dropZone.addEventListener('drop', handleDrop, false);
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        handleFiles(Array.from(dt.files));
    }

    function handleFileSelect(e) {
        handleFiles(Array.from(e.target.files));
    }

    function handleFiles(newFiles) {
        files = newFiles;
        updateFileList();
    }

    function updateFileList() {
        if (files.length === 0) {
            fileList.style.display = 'none';
            return;
        }

        selectedFiles.innerHTML = '';
        let totalBytes = 0;

        files.forEach(file => {
            const li = document.createElement('li');
            li.textContent = `${file.name} (${formatFileSize(file.size)})`;
            selectedFiles.appendChild(li);
            totalBytes += file.size;
        });

        totalFiles.textContent = files.length;
        totalSize.textContent = formatFileSize(totalBytes);
        fileList.style.display = 'block';
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Password visibility toggle
    showPassword.addEventListener('change', () => {
        password.type = showPassword.checked ? 'text' : 'password';
    });

    // Encryption/Decryption functionality
    encryptBtn.addEventListener('click', () => processFiles('encrypt'));
    decryptBtn.addEventListener('click', () => processFiles('decrypt'));

    async function processFiles(action) {
        if (!validateInputs()) return;

        const key = await deriveKey(password.value);
        progress.style.display = 'block';
        
        try {
            const zip = new JSZip();
            const totalFiles = files.length;
            
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                currentFileName.textContent = file.name;
                updateProgress((i / totalFiles) * 100);

                const arrayBuffer = await readFileAsArrayBuffer(file);
                const processedData = await processFile(arrayBuffer, key, action);
                
                const fileName = action === 'encrypt' 
                    ? `${file.name}.enc`
                    : file.name.endsWith('.enc') 
                        ? file.name.slice(0, -4)
                        : `decrypted_${file.name}`;
                
                zip.file(fileName, processedData);
            }

            updateProgress(90);
            const zipBlob = await zip.generateAsync({ type: 'blob' });
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            downloadFile(zipBlob, `${action}ed_files_${timestamp}.zip`);
            
            updateProgress(100);
            setTimeout(() => {
                progress.style.display = 'none';
                updateProgress(0);
                currentFileName.textContent = '-';
            }, 1000);
        } catch (error) {
            console.error('Error processing files:', error);
            alert('Error processing files: ' + error.message);
            progress.style.display = 'none';
            updateProgress(0);
            currentFileName.textContent = '-';
        }
    }

    function validateInputs() {
        if (files.length === 0) {
            alert('Please select at least one file');
            return false;
        }
        if (!password.value) {
            alert('Please enter a password');
            password.focus();
            return false;
        }
        return true;
    }

    async function readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = e => reject(e.target.error);
            reader.readAsArrayBuffer(file);
        });
    }

    async function deriveKey(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return await crypto.subtle.importKey(
            'raw',
            hash,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function processFile(arrayBuffer, key, action) {
        const iv = action === 'encrypt'
            ? crypto.getRandomValues(new Uint8Array(12))
            : new Uint8Array(arrayBuffer.slice(0, 12));

        const data = action === 'encrypt'
            ? arrayBuffer
            : arrayBuffer.slice(12);

        try {
            const result = await crypto.subtle[action]({
                name: 'AES-GCM',
                iv: iv
            }, key, data);

            if (action === 'encrypt') {
                const combined = new Uint8Array(iv.length + result.byteLength);
                combined.set(iv);
                combined.set(new Uint8Array(result), iv.length);
                return combined;
            }
            return result;
        } catch (error) {
            throw new Error(action === 'decrypt' ? 'Decryption failed. Wrong password or corrupted file.' : error.message);
        }
    }

    function updateProgress(percent) {
        progressBar.style.setProperty('--progress', `${percent}%`);
        progressPercent.textContent = `${Math.round(percent)}%`;
    }

    function downloadFile(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    }
});