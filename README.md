# Secure HTML Hosting for iframe Embedding

A professional, secure HTML file hosting service designed specifically for embedding Articulate Storyline courses and other HTML content via iframes in password-protected community portals.

## Features

### 🔐 Security First
- **SSL/TLS Encryption**: All connections secured with HTTPS
- **Content Security Policy (CSP)**: Advanced security headers prevent XSS attacks
- **Rate Limiting**: Built-in DDoS protection and abuse prevention
- **File Validation**: Secure upload validation for HTML and ZIP files
- **Access Control**: Authentication and authorization system
- **iframe Sandboxing**: Safe embedding with proper frame ancestors

### 🚀 Performance Optimized
- **File Compression**: Automatic gzip compression for faster loading
- **Optimized Headers**: Proper caching and security headers
- **Lightweight**: Minimal overhead for maximum performance
- **Mobile Responsive**: Works seamlessly on all devices

### 📊 Management Dashboard
- **Drag & Drop Upload**: Intuitive file upload interface
- **File Management**: View, preview, and delete hosted files
- **Analytics**: Track file uploads and usage statistics
- **Search & Filter**: Easy file organization and discovery
- **One-Click Embed URLs**: Copy-paste ready iframe URLs

## Quick Start

### Prerequisites
- Node.js 16+ and npm
- 100MB+ free disk space for file uploads

### Installation

1. **Clone or download the project**
   ```bash
   cd embedded_iframe
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your settings:
   ```env
   PORT=3000
   NODE_ENV=development
   JWT_SECRET=your-super-secret-jwt-key-here
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your-secure-password
   ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
   ```

4. **Start the server**
   ```bash
   npm start
   ```

5. **Access the application**
   - **Public Site**: http://localhost:3000
   - **Admin Dashboard**: http://localhost:3000/admin

## Usage

### For Administrators

1. **Login to Admin Dashboard**
   - Navigate to `/admin`
   - Use credentials from your `.env` file
   - Default: admin/admin123 (change in production!)

2. **Upload HTML Files**
   - Drag & drop HTML files or ZIP archives
   - Supports Articulate Storyline exports
   - Files are automatically processed and secured

3. **Get Embed URLs**
   - Copy the provided embed URL for each file
   - Use in your iframe tags: `<iframe src="embed-url" frameborder="0"></iframe>`

4. **Manage Files**
   - Preview files before embedding
   - Delete unused files
   - Monitor upload statistics

### For Developers

The service provides a REST API for programmatic access:

```javascript
// Upload file
const formData = new FormData();
formData.append('htmlFile', file);

fetch('/api/upload', {
    method: 'POST',
    body: formData
}).then(response => response.json());

// List files
fetch('/api/files')
    .then(response => response.json());

// Delete file
fetch('/api/files/{id}', { method: 'DELETE' });
```

## Security Configuration

### iframe Embedding Security

The service automatically configures proper security headers for iframe embedding:

- `X-Frame-Options: SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'self' {allowed-origins}`
- Sanitized file uploads with validation
- XSS protection and CSRF prevention

### Allowed Origins

Configure which domains can embed your content:

```env
ALLOWED_ORIGINS=https://yourdomain.com,https://portal.company.com
```

## File Support

### Supported Formats
- **HTML Files**: `.html`, `.htm`
- **ZIP Archives**: `.zip` containing HTML projects
- **Articulate Storyline**: Exported HTML packages
- **SCORM Packages**: Standard e-learning content

### File Limitations
- Maximum file size: 100MB (configurable)
- Automatic virus scanning (basic validation)
- Filename sanitization for security

## Deployment

### Production Deployment

1. **Set environment variables**
   ```env
   NODE_ENV=production
   PORT=443
   JWT_SECRET=your-production-secret-key
   ALLOWED_ORIGINS=https://yourdomain.com
   ```

2. **Use HTTPS**
   - Configure SSL certificates
   - Use a reverse proxy (nginx/Apache)
   - Enable HTTP to HTTPS redirects

3. **Security Hardening**
   - Change default admin credentials
   - Enable firewall rules
   - Regular security updates
   - Monitor access logs

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment | development |
| `JWT_SECRET` | JWT signing key | (required) |
| `SESSION_SECRET` | Session secret | (required) |
| `ADMIN_USERNAME` | Admin username | admin |
| `ADMIN_PASSWORD` | Admin password | admin123 |
| `UPLOAD_DIR` | Upload directory | ./uploads |
| `MAX_FILE_SIZE` | Max file size (MB) | 100 |
| `ALLOWED_ORIGINS` | CORS origins | localhost:3000 |

## Troubleshooting

### Common Issues

**Upload fails**
- Check file size limits
- Verify file format is supported
- Ensure sufficient disk space

**iframe not loading**
- Verify ALLOWED_ORIGINS includes your domain
- Check browser console for CSP errors
- Ensure HTTPS if required

**Authentication issues**
- Verify JWT_SECRET is set
- Check cookie settings in browser
- Clear browser cache and cookies

### Logs

Enable detailed logging:
```env
NODE_ENV=development
```

View server logs for debugging information.

## Contributing

This is a complete, production-ready solution. For customizations:

1. Fork the project
2. Create feature branches
3. Test thoroughly
4. Document changes

## License

MIT License - Use freely for commercial and personal projects.

## Support

For technical issues:
1. Check the troubleshooting guide
2. Review server logs
3. Verify configuration settings
4. Test with minimal setup

---

**Built for professional e-learning content delivery with enterprise-grade security.**