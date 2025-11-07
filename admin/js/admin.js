class AdminDashboard {
    constructor() {
        this.files = [];
        this.init();
    }

    init() {
        this.checkAuth();
        this.bindEvents();
        this.setupDragAndDrop();
    }

    checkAuth() {
        const token = this.getCookie('auth_token');
        if (token) {
            this.showDashboard();
            this.loadFiles();
        } else {
            this.showLogin();
        }
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    showLogin() {
        document.getElementById('loginModal').classList.add('show');
        document.getElementById('dashboard').style.display = 'none';
    }

    showDashboard() {
        document.getElementById('loginModal').classList.remove('show');
        document.getElementById('dashboard').style.display = 'block';
    }

    bindEvents() {
        // Login form
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Logout button
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.handleLogout();
        });

        // Upload form
        document.getElementById('uploadForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleUpload();
        });

        // File input change
        document.getElementById('htmlFile').addEventListener('change', (e) => {
            this.handleFileSelect(e.target.files[0]);
        });

        // Search files
        document.getElementById('searchFiles').addEventListener('input', (e) => {
            this.filterFiles(e.target.value);
        });

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.loadFiles();
        });

        // Modal close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const modal = e.target.closest('.modal');
                this.closeModal(modal);
            });
        });

        // Close modal on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeModal(modal);
                }
            });
        });

        // Close modal on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const openModals = document.querySelectorAll('.modal.show');
                openModals.forEach(modal => this.closeModal(modal));
            }
        });

        // Event delegation for dynamically created buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('.preview-btn')) {
                const button = e.target.closest('.preview-btn');
                const fileId = button.getAttribute('data-file-id');
                this.previewFile(fileId);
            } else if (e.target.closest('.delete-btn')) {
                const button = e.target.closest('.delete-btn');
                const fileId = button.getAttribute('data-file-id');
                this.deleteFile(fileId);
            } else if (e.target.classList.contains('embed-url')) {
                const input = e.target;
                input.select();
                input.setSelectionRange(0, 99999); // For mobile devices
                try {
                    document.execCommand('copy');
                    this.showNotification('URL copied to clipboard!', 'success');
                } catch (err) {
                    // Fallback for modern browsers
                    navigator.clipboard.writeText(input.value).then(() => {
                        this.showNotification('URL copied to clipboard!', 'success');
                    }).catch(() => {
                        this.showNotification('Failed to copy URL', 'error');
                    });
                }
            }
        });
    }

    setupDragAndDrop() {
        const uploadArea = document.getElementById('uploadArea');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.remove('dragover');
            });
        });

        uploadArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelect(files[0]);
            }
        });

        uploadArea.addEventListener('click', () => {
            document.getElementById('htmlFile').click();
        });
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.showNotification('Login successful!', 'success');
                this.showDashboard();
                this.loadFiles();
            } else {
                this.showNotification(data.error || 'Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showNotification('Network error. Please try again.', 'error');
        }
    }

    async handleLogout() {
        try {
            await fetch('/api/auth/logout', { method: 'POST' });
            this.showNotification('Logged out successfully', 'success');
            this.showLogin();
            document.getElementById('loginForm').reset();
        } catch (error) {
            console.error('Logout error:', error);
        }
    }

    handleFileSelect(file) {
        if (!file) return;

        const allowedTypes = ['text/html', 'application/zip', 'application/x-zip-compressed'];
        const allowedExtensions = ['.html', '.htm', '.zip'];
        
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
        
        if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(fileExtension)) {
            this.showNotification('Please select an HTML or ZIP file', 'error');
            return;
        }

        const maxSize = 100 * 1024 * 1024; // 100MB
        if (file.size > maxSize) {
            this.showNotification('File size must be less than 100MB', 'error');
            return;
        }

        // Show file info
        document.querySelector('.file-name').textContent = file.name;
        document.querySelector('.file-size').textContent = this.formatFileSize(file.size);
        document.querySelector('.upload-info').style.display = 'block';
    }

    async handleUpload() {
        const fileInput = document.getElementById('htmlFile');
        const file = fileInput.files[0];

        if (!file) {
            this.showNotification('Please select a file', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('htmlFile', file);

        const progressBar = document.querySelector('.progress-bar');
        const progressFill = document.querySelector('.progress-fill');
        
        progressBar.style.display = 'block';
        progressFill.style.width = '0%';

        try {
            const xhr = new XMLHttpRequest();

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete + '%';
                }
            });

            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    const data = JSON.parse(xhr.responseText);
                    this.showNotification(data.message, 'success');
                    this.loadFiles();
                    this.resetUploadForm();
                } else {
                    const error = JSON.parse(xhr.responseText);
                    this.showNotification(error.error || 'Upload failed', 'error');
                }
                progressBar.style.display = 'none';
            });

            xhr.addEventListener('error', () => {
                this.showNotification('Upload failed. Please try again.', 'error');
                progressBar.style.display = 'none';
            });

            xhr.open('POST', '/api/upload');
            xhr.send(formData);

        } catch (error) {
            console.error('Upload error:', error);
            this.showNotification('Upload failed. Please try again.', 'error');
            progressBar.style.display = 'none';
        }
    }

    resetUploadForm() {
        document.getElementById('uploadForm').reset();
        document.querySelector('.upload-info').style.display = 'none';
    }

    async loadFiles() {
        try {
            const response = await fetch('/api/files', {
                credentials: 'include'
            });
            
            if (response.ok) {
                this.files = await response.json();
                this.renderFiles();
                this.updateStats();
            } else if (response.status === 401) {
                this.showLogin();
            } else {
                this.showNotification('Failed to load files', 'error');
            }
        } catch (error) {
            console.error('Load files error:', error);
            this.showNotification('Failed to load files', 'error');
        }
    }

    renderFiles(filesToRender = this.files) {
        const tbody = document.getElementById('filesTableBody');
        
        if (filesToRender.length === 0) {
            tbody.innerHTML = `
                <tr class="no-files">
                    <td colspan="5">
                        <div class="empty-state">
                            <i class="fas fa-folder-open"></i>
                            <p>No files found</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = filesToRender.map(file => `
            <tr>
                <td>
                    <strong>${this.escapeHtml(file.originalName)}</strong>
                </td>
                <td>${this.formatFileSize(file.size)}</td>
                <td>${this.formatDate(file.uploadDate)}</td>
                <td>
                    <input type="text" class="embed-url" value="${window.location.origin}/embed/${file.id}" 
                           readonly data-copy-text="${window.location.origin}/embed/${file.id}">
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-info btn-sm preview-btn" data-file-id="${file.id}">
                            <i class="fas fa-eye"></i> Preview
                        </button>
                        <button class="btn btn-danger btn-sm delete-btn" data-file-id="${file.id}">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    filterFiles(searchTerm) {
        if (!searchTerm) {
            this.renderFiles();
            return;
        }

        const filtered = this.files.filter(file => 
            file.originalName.toLowerCase().includes(searchTerm.toLowerCase())
        );
        this.renderFiles(filtered);
    }

    updateStats() {
        const totalFiles = this.files.length;
        const totalSize = this.files.reduce((sum, file) => sum + file.size, 0);
        const recentUploads = this.files.filter(file => {
            const uploadDate = new Date(file.uploadDate);
            const dayAgo = new Date();
            dayAgo.setDate(dayAgo.getDate() - 1);
            return uploadDate > dayAgo;
        }).length;

        document.getElementById('totalFiles').textContent = totalFiles;
        document.getElementById('totalSize').textContent = this.formatFileSize(totalSize);
        document.getElementById('recentUploads').textContent = recentUploads;
    }

    previewFile(fileId) {
        const embedUrl = `/embed/${fileId}?preview=true`;
        const previewFrame = document.getElementById('previewFrame');
        const previewModal = document.getElementById('previewModal');
        const previewLoading = document.getElementById('previewLoading');
        const previewError = document.getElementById('previewError');
        
        // Store the current file ID for error handling
        previewModal.dataset.fileId = fileId;
        
        // Reset modal state
        previewLoading.style.display = 'flex';
        previewFrame.style.display = 'none';
        previewError.style.display = 'none';
        previewFrame.src = 'about:blank';
        
        // Show modal
        previewModal.classList.add('show');
        
        // Test if the embed URL is accessible first
        fetch(embedUrl, { 
            method: 'HEAD',
            credentials: 'include'
        })
        .then(response => {
            if (response.ok) {
                // URL is accessible, load in iframe
                previewFrame.src = embedUrl;
                
                // Simple timeout to hide loading - iframe events are unreliable for cross-origin
                setTimeout(() => {
                    this.hidePreviewLoading();
                }, 2000);
            } else {
                console.error('Preview URL not accessible:', response.status);
                this.showPreviewError();
            }
        })
        .catch(error => {
            console.error('Preview fetch error:', error);
            this.showPreviewError();
        });
    }

    async deleteFile(fileId) {
        if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`/api/files/${fileId}`, {
                method: 'DELETE',
                credentials: 'include'
            });

            if (response.ok) {
                this.showNotification('File deleted successfully', 'success');
                this.loadFiles();
            } else {
                const error = await response.json();
                this.showNotification(error.error || 'Delete failed', 'error');
            }
        } catch (error) {
            console.error('Delete error:', error);
            this.showNotification('Delete failed. Please try again.', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            ${message}
            <button class="close" onclick="this.parentElement.remove()">&times;</button>
        `;

        document.getElementById('notifications').appendChild(notification);

        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    hidePreviewLoading() {
        const previewLoading = document.getElementById('previewLoading');
        const previewFrame = document.getElementById('previewFrame');
        
        previewLoading.style.display = 'none';
        previewFrame.style.display = 'block';
    }

    showPreviewError() {
        const previewLoading = document.getElementById('previewLoading');
        const previewFrame = document.getElementById('previewFrame');
        const previewError = document.getElementById('previewError');
        
        previewLoading.style.display = 'none';
        previewFrame.style.display = 'none';
        previewError.style.display = 'flex';
    }

    closeModal(modal) {
        if (modal) {
            modal.classList.remove('show');
            // Special handling for preview modal
            if (modal.id === 'previewModal') {
                const previewFrame = document.getElementById('previewFrame');
                if (previewFrame) {
                    previewFrame.src = 'about:blank';
                }
            }
        }
    }

    closePreview() {
        const previewModal = document.getElementById('previewModal');
        this.closeModal(previewModal);
    }

    openInNewTab() {
        const previewModal = document.getElementById('previewModal');
        const fileId = previewModal.dataset.fileId;
        
        if (fileId) {
            const embedUrl = `/embed/${fileId}?preview=true`;
            window.open(embedUrl, '_blank');
        }
    }
}

// Global functions for HTML onclick handlers
function hidePreviewLoading() {
    if (window.adminDashboard) {
        window.adminDashboard.hidePreviewLoading();
    }
}

function showPreviewError() {
    if (window.adminDashboard) {
        window.adminDashboard.showPreviewError();
    }
}

function closePreview() {
    if (window.adminDashboard) {
        window.adminDashboard.closePreview();
    }
}

function openInNewTab() {
    if (window.adminDashboard) {
        window.adminDashboard.openInNewTab();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminDashboard = new AdminDashboard();
});