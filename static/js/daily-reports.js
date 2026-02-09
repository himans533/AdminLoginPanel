/**
 * Daily Task Reporting Module
 * Handles all client-side operations for daily reports across roles
 * Features: Submit, View, Filter, Approve, Reject, Export
 */

class DailyReportModule {
    constructor() {
        this.reports = [];
        this.filters = {
            startDate: '',
            endDate: '',
            employeeId: '',
            projectId: '',
            taskId: '',
            status: '',
            approvalStatus: ''
        };
        this.currentPage = 1;
        this.perPage = 50;
        this.totalReports = 0;
        this.userRole = this.getUserRole();
        this.userId = this.getUserId();
    }

    /**
     * Get current user's role from session/localStorage
     */
    getUserRole() {
        // Try multiple sources for user role
        if (window.currentUserRole) return window.currentUserRole;
        if (sessionStorage.getItem('user_type')) return sessionStorage.getItem('user_type');
        if (localStorage.getItem('user_type')) return localStorage.getItem('user_type');
        return 'employee'; // default
    }

    /**
     * Get current user ID from session/localStorage
     */
    getUserId() {
        if (window.currentUserId) return window.currentUserId;
        if (sessionStorage.getItem('user_id')) return sessionStorage.getItem('user_id');
        if (localStorage.getItem('user_id')) return localStorage.getItem('user_id');
        return null;
    }

    /**
     * Submit a new daily report
     */
    async submitReport(reportData) {
        try {
            const endpoint = '/api/daily-report';
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    task_id: reportData.taskId,
                    project_id: reportData.projectId,
                    report_date: reportData.reportDate || new Date().toISOString().split('T')[0],
                    work_description: reportData.workDescription,
                    time_spent: parseFloat(reportData.timeSpent) || 0,
                    status: reportData.status || 'In Progress',
                    blocker: reportData.blocker || ''
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to submit report');
            }

            const result = await response.json();
            this.showNotification('Report submitted successfully!', 'success');
            return result;
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Submit report error:', error);
            throw error;
        }
    }

    /**
     * Fetch daily reports with filters
     */
    async fetchReports(page = 1) {
        try {
            const queryParams = new URLSearchParams();
            queryParams.append('page', page);
            queryParams.append('per_page', this.perPage);

            if (this.filters.startDate) queryParams.append('start_date', this.filters.startDate);
            if (this.filters.endDate) queryParams.append('end_date', this.filters.endDate);
            if (this.filters.employeeId) queryParams.append('employee_id', this.filters.employeeId);
            if (this.filters.projectId) queryParams.append('project_id', this.filters.projectId);
            if (this.filters.taskId) queryParams.append('task_id', this.filters.taskId);
            if (this.filters.status) queryParams.append('status', this.filters.status);
            if (this.filters.approvalStatus) queryParams.append('approval_status', this.filters.approvalStatus);

            const response = await fetch(`/api/daily-reports?${queryParams}`, {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch reports');

            const data = await response.json();
            this.reports = Array.isArray(data.data) ? data.data : data;
            this.totalReports = data.total || this.reports.length;
            this.currentPage = page;
            return this.reports;
        } catch (error) {
            console.error('Fetch reports error:', error);
            this.showNotification('Failed to load reports', 'error');
            throw error;
        }
    }

    /**
     * Get a single report by ID
     */
    async getReport(reportId) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}`, {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Report not found');
            return await response.json();
        } catch (error) {
            console.error('Get report error:', error);
            throw error;
        }
    }

    /**
     * Edit a report (employee: own pending; admin: any)
     */
    async editReport(reportId, updates) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}`, {
                method: 'PUT',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    work_description: updates.workDescription,
                    time_spent: parseFloat(updates.timeSpent),
                    status: updates.status,
                    blocker: updates.blocker
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to update report');
            }

            this.showNotification('Report updated successfully!', 'success');
            return await response.json();
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Edit report error:', error);
            throw error;
        }
    }

    /**
     * Approve a report (admin only)
     */
    async approveReport(reportId, comment = '') {
        try {
            const response = await fetch(`/api/daily-report/${reportId}/action`, {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    action: 'approve',
                    comment: comment
                })
            });

            if (!response.ok) throw new Error('Failed to approve report');
            this.showNotification('Report approved!', 'success');
            return await response.json();
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Approve error:', error);
            throw error;
        }
    }

    /**
     * Reject a report (admin only)
     */
    async rejectReport(reportId, comment = '') {
        try {
            const response = await fetch(`/api/daily-report/${reportId}/action`, {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    action: 'reject',
                    comment: comment
                })
            });

            if (!response.ok) throw new Error('Failed to reject report');
            this.showNotification('Report rejected!', 'success');
            return await response.json();
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Reject error:', error);
            throw error;
        }
    }

    /**
     * Delete a report (super admin only)
     */
    async deleteReport(reportId) {
        if (!confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`/api/daily-report/${reportId}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to delete report');
            this.showNotification('Report deleted!', 'success');
            return await response.json();
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Delete error:', error);
            throw error;
        }
    }

    /**
     * Add comment to report
     */
    async addComment(reportId, comment, isInternal = false) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}/comments`, {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    comment: comment,
                    internal: isInternal
                })
            });

            if (!response.ok) throw new Error('Failed to add comment');
            this.showNotification('Comment added!', 'success');
            return await response.json();
        } catch (error) {
            this.showNotification(error.message, 'error');
            console.error('Add comment error:', error);
            throw error;
        }
    }

    /**
     * Export reports to CSV
     */
    async exportReports() {
        try {
            const queryParams = new URLSearchParams();
            if (this.filters.startDate) queryParams.append('start_date', this.filters.startDate);
            if (this.filters.endDate) queryParams.append('end_date', this.filters.endDate);
            if (this.filters.employeeId) queryParams.append('employee_id', this.filters.employeeId);
            if (this.filters.projectId) queryParams.append('project_id', this.filters.projectId);
            if (this.filters.taskId) queryParams.append('task_id', this.filters.taskId);

            const response = await fetch(`/api/daily-reports/export?${queryParams}`, {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to export');

            // Get filename from header if available
            const disposition = response.headers.get('content-disposition');
            const filename = disposition 
                ? disposition.split('filename=')[1].trim('"')
                : `daily_reports_${new Date().toISOString().split('T')[0]}.csv`;

            const blob = await response.blob();
            this.downloadBlob(blob, filename);
            this.showNotification('Reports exported successfully!', 'success');
        } catch (error) {
            this.showNotification('Export failed: ' + error.message, 'error');
            console.error('Export error:', error);
        }
    }

    /**
     * Get dashboard statistics (admin/super admin)
     */
    async getDashboardStats() {
        try {
            const response = await fetch('/api/daily-reports/stats', {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch stats');
            return await response.json();
        } catch (error) {
            console.error('Stats error:', error);
            return null;
        }
    }

    /**
     * Set report filters
     */
    setFilters(filters) {
        this.filters = { ...this.filters, ...filters };
    }

    /**
     * Clear all filters
     */
    clearFilters() {
        this.filters = {
            startDate: '',
            endDate: '',
            employeeId: '',
            projectId: '',
            taskId: '',
            status: '',
            approvalStatus: ''
        };
    }

    /**
     * Get authorization token
     */
    getAuthToken() {
        // Check for different token storage keys based on user type
        const adminToken = sessionStorage.getItem('admin_session_token') || localStorage.getItem('admin_session_token');
        const employeeToken = sessionStorage.getItem('employee_token') || localStorage.getItem('employee_token');
        const sessionToken = sessionStorage.getItem('session_token') || localStorage.getItem('session_token');
        
        return adminToken || employeeToken || sessionToken || '';
    }

    /**
     * Get headers for authenticated requests (includes X-CSRF-Token when available)
     * @param {string} contentType - optional Content-Type to include
     */
    getAuthHeaders(contentType) {
        const headers = {};
        const token = this.getAuthToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const storedCsrf = localStorage.getItem('csrf_token') || sessionStorage.getItem('csrf_token');
        const metaCsrf = (typeof document !== 'undefined' && document.querySelector) ? document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') : null;
        const csrf = storedCsrf || metaCsrf;
        if (csrf) headers['X-CSRF-Token'] = csrf;
        if (contentType) headers['Content-Type'] = contentType;
        return headers;
    }

    /**
     * Show toast notification
     */
    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container') || this.createNotificationContainer();
        
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'info'} alert-dismissible fade show`;
        toast.role = 'alert';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }

    /**
     * Create notification container if it doesn't exist
     */
    createNotificationContainer() {
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
            document.body.appendChild(container);
        }
        return container;
    }

    /**
     * Download blob as file
     */
    downloadBlob(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }

    /**
     * Format date for display
     */
    formatDate(dateStr) {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    }

    /**
     * Format time for display
     */
    formatTime(hours) {
        return parseFloat(hours).toFixed(2) + ' hrs';
    }

    /**
     * Get status badge class
     */
    getStatusBadgeClass(status) {
        const statusMap = {
            'In Progress': 'badge bg-info',
            'Completed': 'badge bg-success',
            'Blocked': 'badge bg-danger'
        };
        return statusMap[status] || 'badge bg-secondary';
    }

    /**
     * Get approval status badge class
     */
    getApprovalBadgeClass(status) {
        const statusMap = {
            'pending': 'badge bg-warning text-dark',
            'approved': 'badge bg-success',
            'rejected': 'badge bg-danger'
        };
        return statusMap[status] || 'badge bg-secondary';
    }

    /**
     * Render report as HTML row
     */
    renderReportRow(report) {
        const approvalBadge = `<span class="${this.getApprovalBadgeClass(report.approval_status)}">${report.approval_status}</span>`;
        const statusBadge = `<span class="${this.getStatusBadgeClass(report.status)}">${report.status}</span>`;
        
        return `
            <tr data-report-id="${report.id}">
                <td>${this.formatDate(report.report_date)}</td>
                <td>${report.employee_name || 'N/A'}</td>
                <td>${report.project_title || 'N/A'}</td>
                <td title="${report.work_description}">${report.work_description?.substring(0, 50) || 'N/A'}...</td>
                <td>${this.formatTime(report.time_spent)}</td>
                <td>${statusBadge}</td>
                <td>${approvalBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary view-report" title="View">
                        <i class="fas fa-eye"></i>
                    </button>
                    ${this.userRole === 'admin' ? `
                        <button class="btn btn-sm btn-outline-success approve-report" title="Approve">
                            <i class="fas fa-check"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger reject-report" title="Reject">
                            <i class="fas fa-times"></i>
                        </button>
                    ` : ''}
                    ${this.userRole === 'super admin' ? `
                        <button class="btn btn-sm btn-outline-warning edit-report" title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger delete-report" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    }
}

// Initialize module globally
const dailyReportModule = new DailyReportModule();
