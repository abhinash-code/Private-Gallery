/**
 * Encrypted Image Gallery Application
 * 
 * Cryptographic Parameters:
 * - Algorithm: AES-GCM (256-bit) - Provides authenticated encryption
 * - Key Derivation: PBKDF2 with SHA-256, 100,000 iterations
 * - Salt: 16 bytes randomly generated per encryption session
 * - IV: 12 bytes randomly generated per file (optimal for GCM)
 * 
 * Security Notes:
 * - Client-side encryption protects against casual access
 * - Weak passwords are vulnerable to brute-force attacks
 * - Source code is always visible in static sites
 * - Use strong passwords (12+ characters, mixed case, numbers, symbols)
 */

class EncryptedGallery {
    constructor() {
        this.currentPassword = '';
        this.isAdminMode = false;
        this.attemptCount = 0;
        this.lastAttemptTime = 0;
        this.selectedFiles = [];
        this.currentImageBlob = null;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadEncryptedData();
        
        // Focus password input on load
        document.getElementById('password-input').focus();
    }

    bindEvents() {
        // Password screen events
        document.getElementById('password-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.handleUnlock();
            }
        });
        
        document.getElementById('unlock-btn').addEventListener('click', () => {
            this.handleUnlock();
        });
        
        document.getElementById('admin-mode-toggle').addEventListener('change', (e) => {
            this.isAdminMode = e.target.checked;
        });

        // Gallery events
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });

        // Admin events
        document.getElementById('admin-logout-btn').addEventListener('click', () => {
            this.logout();
        });
        
        document.getElementById('file-input').addEventListener('change', (e) => {
            this.handleFileSelection(e);
        });
        
        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportEncryptedData();
        });
        
        document.getElementById('copy-btn').addEventListener('click', () => {
            this.copyToClipboard();
        });

        // Lightbox events
        document.getElementById('lightbox').addEventListener('click', (e) => {
            if (e.target.classList.contains('lightbox-backdrop') || e.target.classList.contains('lightbox-close')) {
                this.closeLightbox();
            }
        });
        
        document.getElementById('download-btn').addEventListener('click', () => {
            this.downloadCurrentImage();
        });
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeLightbox();
            }
        });
    }

    loadEncryptedData() {
        // encryptedImages is loaded from encrypted-data-example.js
        if (typeof encryptedImages === 'undefined') {
            console.warn('No encrypted data found. Use admin mode to add images.');
        }
    }

    async handleUnlock() {
        const password = document.getElementById('password-input').value;
        const errorElement = document.getElementById('error-message');
        
        if (!password) {
            this.showError('Please enter a password');
            return;
        }

        // Rate limiting
        const now = Date.now();
        const timeSinceLastAttempt = now - this.lastAttemptTime;
        const requiredDelay = Math.pow(2, Math.max(0, this.attemptCount - 3)) * 1000;
        
        if (timeSinceLastAttempt < requiredDelay) {
            const remainingTime = Math.ceil((requiredDelay - timeSinceLastAttempt) / 1000);
            this.showError(`Too many attempts. Try again in ${remainingTime} seconds.`);
            return;
        }

        this.showLoading(true);
        
        try {
            if (this.isAdminMode) {
                // For admin mode, just store the password (no validation against encrypted data)
                this.currentPassword = password;
                this.showAdminScreen();
                this.resetAttempts();
            } else {
                // Validate password by attempting to decrypt first image
                if (typeof encryptedImages === 'undefined' || !encryptedImages.images || encryptedImages.images.length === 0) {
                    this.showError('No encrypted images found. Use admin mode to add images.');
                    return;
                }
                
                const success = await this.validatePassword(password);
                if (success) {
                    this.currentPassword = password;
                    this.showGalleryScreen();
                    this.resetAttempts();
                } else {
                    this.attemptCount++;
                    this.lastAttemptTime = now;
                    this.showError('Incorrect password');
                }
            }
        } catch (error) {
            console.error('Unlock error:', error);
            this.showError('An error occurred. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    async validatePassword(password) {
        try {
            const firstImage = encryptedImages.images[0];
            const key = await this.deriveKey(password, firstImage.salt, encryptedImages.iterations || 100000);
            await this.decryptArrayBuffer(key, firstImage.iv, firstImage.data);
            return true;
        } catch {
            return false;
        }
    }

    showError(message) {
        const errorElement = document.getElementById('error-message');
        errorElement.textContent = message;
        errorElement.classList.add('show');
        
        setTimeout(() => {
            errorElement.classList.remove('show');
        }, 5000);
    }

    resetAttempts() {
        this.attemptCount = 0;
        this.lastAttemptTime = 0;
    }

    showLoading(show) {
        document.getElementById('loading').style.display = show ? 'flex' : 'none';
    }

    showGalleryScreen() {
        this.switchScreen('gallery-screen');
        this.loadGalleryImages();
    }

    showAdminScreen() {
        this.switchScreen('admin-screen');
        this.selectedFiles = [];
        this.updateFilePreview();
    }

    switchScreen(screenId) {
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });
        
        setTimeout(() => {
            document.getElementById(screenId).classList.add('active');
        }, 100);
    }

    logout() {
        this.currentPassword = '';
        this.isAdminMode = false;
        this.selectedFiles = [];
        document.getElementById('password-input').value = '';
        document.getElementById('admin-mode-toggle').checked = false;
        document.getElementById('error-message').classList.remove('show');
        this.switchScreen('password-screen');
        
        setTimeout(() => {
            document.getElementById('password-input').focus();
        }, 200);
    }

    async loadGalleryImages() {
        const container = document.getElementById('gallery-container');
        const emptyState = document.getElementById('empty-gallery');
        
        if (typeof encryptedImages === 'undefined' || !encryptedImages.images || encryptedImages.images.length === 0) {
            container.innerHTML = '';
            emptyState.style.display = 'block';
            return;
        }

        emptyState.style.display = 'none';
        container.innerHTML = '';

        for (let i = 0; i < encryptedImages.images.length; i++) {
            const imageData = encryptedImages.images[i];
            try {
                const decryptedData = await this.decryptImage(imageData);
                this.createGalleryItem(container, decryptedData, imageData.title, i);
            } catch (error) {
                console.error(`Failed to decrypt image ${i}:`, error);
            }
        }
    }

    async decryptImage(imageData) {
        const key = await this.deriveKey(this.currentPassword, imageData.salt, encryptedImages.iterations || 100000);
        const decryptedBuffer = await this.decryptArrayBuffer(key, imageData.iv, imageData.data);
        const blob = new Blob([decryptedBuffer], { type: imageData.type });
        return URL.createObjectURL(blob);
    }

    createGalleryItem(container, imageSrc, title, index) {
        const item = document.createElement('div');
        item.className = 'gallery-item';
        item.setAttribute('tabindex', '0');
        item.setAttribute('role', 'button');
        item.setAttribute('aria-label', `View image: ${title}`);
        
        item.innerHTML = `
            <img src="${imageSrc}" alt="${title}" loading="lazy">
            <div class="gallery-item-info">
                <h3>${title || 'Untitled'}</h3>
                <p>Click to view full size</p>
            </div>
        `;
        
        const clickHandler = () => this.openLightbox(index);
        item.addEventListener('click', clickHandler);
        item.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                clickHandler();
            }
        });
        
        container.appendChild(item);
    }

    async openLightbox(index) {
        const imageData = encryptedImages.images[index];
        const imageSrc = await this.decryptImage(imageData);
        
        // Store blob for download
        const key = await this.deriveKey(this.currentPassword, imageData.salt, encryptedImages.iterations || 100000);
        const decryptedBuffer = await this.decryptArrayBuffer(key, imageData.iv, imageData.data);
        this.currentImageBlob = new Blob([decryptedBuffer], { type: imageData.type });
        this.currentImageTitle = imageData.title || 'untitled';
        
        document.getElementById('lightbox-image').src = imageSrc;
        document.getElementById('lightbox-title').textContent = imageData.title || 'Untitled';
        document.getElementById('lightbox').classList.add('active');
    }

    closeLightbox() {
        document.getElementById('lightbox').classList.remove('active');
        this.currentImageBlob = null;
        this.currentImageTitle = '';
    }

    downloadCurrentImage() {
        if (!this.currentImageBlob) return;
        
        const url = URL.createObjectURL(this.currentImageBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${this.currentImageTitle}.jpg`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    handleFileSelection(event) {
        const files = Array.from(event.target.files);
        this.selectedFiles = files.map(file => ({
            file,
            title: file.name.replace(/\.[^/.]+$/, ''), // Remove extension
            preview: null
        }));
        
        this.updateFilePreview();
        document.getElementById('export-btn').disabled = files.length === 0;
    }

    async updateFilePreview() {
        const container = document.getElementById('file-previews');
        container.innerHTML = '';

        for (let i = 0; i < this.selectedFiles.length; i++) {
            const fileData = this.selectedFiles[i];
            const preview = await this.createFilePreview(fileData, i);
            container.appendChild(preview);
        }
    }

    createFilePreview(fileData, index) {
        return new Promise((resolve) => {
            const div = document.createElement('div');
            div.className = 'file-preview';
            
            const reader = new FileReader();
            reader.onload = (e) => {
                div.innerHTML = `
                    <img src="${e.target.result}" alt="Preview">
                    <input type="text" value="${fileData.title}" placeholder="Enter title" 
                           onchange="gallery.updateFileTitle(${index}, this.value)">
                `;
                resolve(div);
            };
            reader.readAsDataURL(fileData.file);
        });
    }

    updateFileTitle(index, title) {
        if (this.selectedFiles[index]) {
            this.selectedFiles[index].title = title;
        }
    }

    async exportEncryptedData() {
        if (this.selectedFiles.length === 0) return;

        this.showLoading(true);

        try {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iterations = 100000;
            const key = await this.deriveKey(this.currentPassword, salt, iterations);
            
            const encryptedImages = [];

            for (const fileData of this.selectedFiles) {
                const arrayBuffer = await this.fileToArrayBuffer(fileData.file);
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encryptedData = await this.encryptArrayBuffer(key, iv, arrayBuffer);
                
                encryptedImages.push({
                    title: fileData.title,
                    type: fileData.file.type,
                    salt: this.arrayBufferToBase64(salt),
                    iv: this.arrayBufferToBase64(iv),
                    data: this.arrayBufferToBase64(encryptedData)
                });
            }

            const exportData = {
                version: '1.0',
                iterations: iterations,
                images: encryptedImages
            };

            this.generatedData = `// Encrypted Gallery Data - Generated ${new Date().toISOString()}
// Replace this file in your repository and commit to GitHub Pages

const encryptedImages = ${JSON.stringify(exportData, null, 2)};`;

            this.downloadEncryptedData();
            document.getElementById('copy-btn').style.display = 'inline-block';
            
        } catch (error) {
            console.error('Export error:', error);
            alert('Error exporting data. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    downloadEncryptedData() {
        const blob = new Blob([this.generatedData], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'encrypted-data.js';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async copyToClipboard() {
        try {
            await navigator.clipboard.writeText(this.generatedData);
            const btn = document.getElementById('copy-btn');
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.textContent = originalText;
            }, 2000);
        } catch (error) {
            console.error('Copy error:', error);
            alert('Could not copy to clipboard. Please download the file instead.');
        }
    }

    // Utility function to convert File to ArrayBuffer
    fileToArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    // Cryptographic Helper Functions
    
    /**
     * Derives a cryptographic key from password using PBKDF2
     * @param {string} password - User password
     * @param {Uint8Array|string} salt - Salt for key derivation
     * @param {number} iterations - Number of PBKDF2 iterations
     * @returns {Promise<CryptoKey>} Derived key
     */
    async deriveKey(password, salt, iterations = 100000) {
        const saltBuffer = typeof salt === 'string' ? this.base64ToArrayBuffer(salt) : salt;
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypts an ArrayBuffer using AES-GCM
     * @param {CryptoKey} key - Encryption key
     * @param {Uint8Array|string} iv - Initialization vector
     * @param {ArrayBuffer} arrayBuffer - Data to encrypt
     * @returns {Promise<ArrayBuffer>} Encrypted data
     */
    async encryptArrayBuffer(key, iv, arrayBuffer) {
        const ivBuffer = typeof iv === 'string' ? this.base64ToArrayBuffer(iv) : iv;
        return crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            key,
            arrayBuffer
        );
    }

    /**
     * Decrypts an ArrayBuffer using AES-GCM
     * @param {CryptoKey} key - Decryption key
     * @param {Uint8Array|string} iv - Initialization vector
     * @param {ArrayBuffer|string} ciphertext - Data to decrypt
     * @returns {Promise<ArrayBuffer>} Decrypted data
     */
    async decryptArrayBuffer(key, iv, ciphertext) {
        const ivBuffer = typeof iv === 'string' ? this.base64ToArrayBuffer(iv) : iv;
        const ciphertextBuffer = typeof ciphertext === 'string' ? this.base64ToArrayBuffer(ciphertext) : ciphertext;
        
        return crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            key,
            ciphertextBuffer
        );
    }

    /**
     * Converts ArrayBuffer to Base64 string
     * @param {ArrayBuffer} buffer - Buffer to convert
     * @returns {string} Base64 encoded string
     */
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Converts Base64 string to ArrayBuffer
     * @param {string} base64 - Base64 encoded string
     * @returns {ArrayBuffer} Decoded buffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Initialize the gallery when DOM is loaded
let gallery;
document.addEventListener('DOMContentLoaded', () => {
    gallery = new EncryptedGallery();
});