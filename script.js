class FileEncryption {
    constructor() {
        this.currentFile = null;
        this.setupEventListeners();
    }

    setupEventListeners() {
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const showPassword = document.getElementById('showPassword');
        const passwordInput = document.getElementById('password');
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');

        // Drag and drop handlers
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            this.handleFiles(e.dataTransfer.files);
        });

        // Click to upload
        dropZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => this.handleFiles(fileInput.files));

        // Show/hide password
        showPassword.addEventListener('change', () => {
            passwordInput.type = showPassword.checked ? 'text' : 'password';
        });

        // Encrypt/Decrypt buttons
        encryptBtn.addEventListener('click', () => this.processFile('encrypt'));
        decryptBtn.addEventListener('click', () => this.processFile('decrypt'));
    }

    handleFiles(files) {
        if (files.length === 0) return;
        
        this.currentFile = files[0];
        document.getElementById('fileName').textContent = this.currentFile.name;
        document.getElementById('fileInfo').style.display = 'block';
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (event) => {
                const arrayBuffer = event.target.result;
                resolve(new Uint8Array(arrayBuffer));
            };
            reader.onerror = (error) => reject(error);
            reader.readAsArrayBuffer(file);
        });
    }

    async processFile(action) {
        if (!this.currentFile) {
            alert('Please select a file first');
            return;
        }
        if (!document.getElementById('password').value) {
            alert('Please enter a password');
            return;
        }

        const progress = document.querySelector('.progress');
        const progressBar = document.querySelector('.progress-bar');
        const progressText = document.querySelector('.progress-text span');

        try {
            progress.style.display = 'block';
            progressBar.style.width = '0%';
            progressText.textContent = '0%';

            const fileContent = await this.readFile(this.currentFile);
            
            // Update progress
            progressBar.style.width = '50%';
            progressText.textContent = '50%';

            let result, fileName;
            const password = document.getElementById('password').value;

            if (action === 'encrypt') {
                const salt = CryptoJS.lib.WordArray.random(128/8);
                const key = this.deriveKey(password, salt);
                result = this.encrypt(fileContent, key, salt);
                fileName = this.currentFile.name + '.enc';
            } else {
                if (!this.currentFile.name.endsWith('.enc')) {
                    throw new Error('Not an encrypted file. Please select a .enc file to decrypt.');
                }
                const { decrypted } = await this.decrypt(fileContent, password);
                result = decrypted;
                fileName = this.getOriginalFileName(this.currentFile.name);
            }

            // Update progress
            progressBar.style.width = '75%';
            progressText.textContent = '75%';

            if (!result || result.length === 0) {
                throw new Error(action === 'encrypt' ? 'Encryption failed' : 'Decryption failed');
            }

            // Create and download file
            const blob = new Blob([result], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Complete progress
            progressBar.style.width = '100%';
            progressText.textContent = '100%';

            setTimeout(() => {
                progress.style.display = 'none';
            }, 2000);

        } catch (error) {
            progress.style.display = 'none';
            alert(error.message || 'An error occurred during file processing');
            console.error(error);
        }
    }

    deriveKey(password, salt) {
        return CryptoJS.PBKDF2(password, salt, {
            keySize: 256/32,
            iterations: 10000 // Increased iterations for better security
        });
    }

    encrypt(content, key, salt) {
        try {
            const wordArray = CryptoJS.lib.WordArray.create(content);
            const iv = CryptoJS.lib.WordArray.random(128/8);
            
            // Store original file metadata
            const fileType = this.currentFile.type;
            const fileExt = this.getFileExtension(this.currentFile.name);
            const metaData = JSON.stringify({
                type: fileType,
                ext: fileExt,
                size: content.byteLength
            });
            
            const metaWordArray = CryptoJS.enc.Utf8.parse(metaData);
            const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
                iv: iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC
            });

            // Format: [salt(16)] + [iv(16)] + [metalength(4)] + [metadata(var)] + [content(var)]
            const metaLength = new Uint32Array([metaWordArray.sigBytes]);
            const metaLengthBytes = new Uint8Array(metaLength.buffer);
            
            const combined = new Uint8Array(
                16 + 16 + 4 + metaWordArray.sigBytes + encrypted.ciphertext.sigBytes
            );

            combined.set(this.wordArrayToUint8Array(salt), 0);
            combined.set(this.wordArrayToUint8Array(iv), 16);
            combined.set(metaLengthBytes, 32);
            combined.set(this.wordArrayToUint8Array(metaWordArray), 36);
            combined.set(
                this.wordArrayToUint8Array(encrypted.ciphertext), 
                36 + metaWordArray.sigBytes
            );

            return combined;
        } catch (e) {
            throw new Error('Encryption failed: ' + e.message);
        }
    }

    async decrypt(content, password) {
        try {
            // Extract components
            const salt = content.slice(0, 16);
            const iv = content.slice(16, 32);
            const metaLengthBytes = content.slice(32, 36);
            const metaLength = new Uint32Array(metaLengthBytes.buffer)[0];
            
            const metaData = content.slice(36, 36 + metaLength);
            const encryptedContent = content.slice(36 + metaLength);

            // Derive key
            const key = this.deriveKey(password, CryptoJS.lib.WordArray.create(salt));
            
            // Decrypt metadata
            const metaWordArray = CryptoJS.lib.WordArray.create(metaData);
            const fileInfo = JSON.parse(
                CryptoJS.enc.Utf8.stringify(metaWordArray)
            );

            // Decrypt content
            const encrypted = CryptoJS.lib.WordArray.create(encryptedContent);
            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: encrypted },
                key,
                { 
                    iv: CryptoJS.lib.WordArray.create(iv),
                    padding: CryptoJS.pad.Pkcs7,
                    mode: CryptoJS.mode.CBC
                }
            );

            // Verify decryption
            if (decrypted.sigBytes <= 0) {
                throw new Error('Decryption failed');
            }

            return {
                key,
                decrypted: this.wordArrayToUint8Array(decrypted)
            };
        } catch (e) {
            throw new Error('Decryption failed: Invalid password or corrupted file');
        }
    }

    getFileExtension(filename) {
        return filename.split('.').pop().toLowerCase();
    }

    getOriginalFileName(encryptedName) {
        return encryptedName.replace(/\.enc$/, '');
    }

    wordArrayToUint8Array(wordArray) {
        const len = wordArray.sigBytes;
        const words = wordArray.words;
        const uint8Array = new Uint8Array(len);
        let i = 0;
        for (let count = 0; count < len; count++) {
            uint8Array[count] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            i++;
        }
        return uint8Array;
    }
}

// Initialize the encryption system
new FileEncryption();