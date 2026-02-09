/**
 * Daily Task Reporting Module
 * Handles employee report submission, admin approval workflow, and super admin dashboard
 */

class DailyReportManager {
    constructor() {
        this.currentUser = null;
        this.currentUserType = null;
        this.reports = [];
        this.filters = {};
        this.currentPage = 1;
        this.pageSize = 25;
    }

    /**
     * Initialize the manager with user info
     */
    async init(userId, userType) {
        this.currentUser = userId;
        this.currentUserType = userType;
        console.log(`[DailyReportManager] Initialized for User ${userId} (Type: ${userType})`);
    }

    /**
     * EMPLOYEE: Submit a daily report
     * @param {Object} reportData - {task_id, project_id, report_date, work_description, time_spent, status, blocker}
     * @returns {Promise}
     */
    async submitReport(reportData) {
        try {
            const payload = {
                task_id: reportData.task_id,
                project_id: reportData.project_id,
                report_date: reportData.report_date || new Date().toISOString().split('T')[0],
                work_description: reportData.work_description,
                time_spent: parseFloat(reportData.time_spent) || 0,
                status: reportData.status || 'In Progress',
                blocker: reportData.blocker || ''
            };

            // Validate time_spent
            if (payload.time_spent < 0 || payload.time_spent > 24) {
                throw new Error('Hours spent must be between 0 and 24');
            }

            const response = await fetch('/api/daily-report', {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to submit report');
            }

            const result = await response.json();
            console.log('[DailyReportManager] Report submitted:', result);
            return { success: true, id: result.id };
        } catch (error) {
            console.error('[DailyReportManager] Error submitting report:', error);
            throw error;
        }
    }

    /**
     * Get daily reports with filters
     * @param {Object} filters - {start_date, end_date, employee_id, project_id, task_id, status, page, per_page}
     * @returns {Promise}
     */
    async getReports(filters = {}) {
        try {
            const params = new URLSearchParams();
            params.append('page', filters.page || 1);
            params.append('per_page', filters.per_page || this.pageSize);

            if (filters.start_date) params.append('start_date', filters.start_date);
            if (filters.end_date) params.append('end_date', filters.end_date);
            if (filters.employee_id) params.append('employee_id', filters.employee_id);
            if (filters.project_id) params.append('project_id', filters.project_id);
            if (filters.task_id) params.append('task_id', filters.task_id);
            if (filters.status) params.append('status', filters.status);

            const response = await fetch(`/api/daily-reports?${params}`, {
                method: 'GET',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                throw new Error('Failed to fetch reports');
            }

            const result = await response.json();
            this.reports = result.data || [];
            return result;
        } catch (error) {
            console.error('[DailyReportManager] Error fetching reports:', error);
            throw error;
        }
    }

    /**
     * ADMIN: Get team daily reports
     */
    async getAdminReports(filters = {}) {
        return this.getReports(filters);
    }

    /**
     * SUPER ADMIN: Get all reports across system
     */
    async getAllReports(filters = {}) {
        return this.getReports(filters);
    }

    /**
     * ADMIN/SUPER ADMIN: Approve a report
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

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to approve report');
            }

            console.log(`[DailyReportManager] Report ${reportId} approved`);
            return { success: true };
        } catch (error) {
            console.error('[DailyReportManager] Error approving report:', error);
            throw error;
        }
    }

    /**
     * ADMIN/SUPER ADMIN: Reject a report
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

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to reject report');
            }

            console.log(`[DailyReportManager] Report ${reportId} rejected`);
            return { success: true };
        } catch (error) {
            console.error('[DailyReportManager] Error rejecting report:', error);
            throw error;
        }
    }

    /**
     * SUPER ADMIN: Edit a report
     */
    async editReport(reportId, updates) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}`, {
                method: 'PUT',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify(updates)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to edit report');
            }

            console.log(`[DailyReportManager] Report ${reportId} edited`);
            return { success: true };
        } catch (error) {
            console.error('[DailyReportManager] Error editing report:', error);
            throw error;
        }
    }

    /**
     * SUPER ADMIN: Delete a report
     */
    async deleteReport(reportId) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to delete report');
            }

            console.log(`[DailyReportManager] Report ${reportId} deleted`);
            return { success: true };
        } catch (error) {
            console.error('[DailyReportManager] Error deleting report:', error);
            throw error;
        }
    }

    /**
     * Add comment to a report (internal or visible)
     */
    async addComment(reportId, comment, internal = false) {
        try {
            const response = await fetch(`/api/daily-report/${reportId}/comments`, {
                method: 'POST',
                headers: this.getAuthHeaders('application/json'),
                body: JSON.stringify({
                    comment: comment,
                    internal: internal
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to add comment');
            }

            console.log(`[DailyReportManager] Comment added to report ${reportId}`);
            return { success: true };
        } catch (error) {
            console.error('[DailyReportManager] Error adding comment:', error);
            throw error;
        }
    }

    /**
     * Export reports to CSV
     */
    async exportReports(filters = {}) {
        try {
            const params = new URLSearchParams();
            if (filters.start_date) params.append('start_date', filters.start_date);
            if (filters.end_date) params.append('end_date', filters.end_date);
            if (filters.employee_id) params.append('employee_id', filters.employee_id);
            if (filters.project_id) params.append('project_id', filters.project_id);
            if (filters.task_id) params.append('task_id', filters.task_id);

            const url = `/api/daily-reports/export?${params}`;
            window.location.href = url;
        } catch (error) {
            console.error('[DailyReportManager] Error exporting reports:', error);
            throw error;
        }
    }

    /**
     * Get summary statistics (Super Admin Dashboard)
     */
    async getSummaryStats() {
        try {
            const result = await this.getReports({ per_page: 1 });
            const total = result.total || 0;

            const allReports = await this.getReports({ per_page: 10000 });
            const data = allReports.data || [];

            const stats = {
                total: total,
                approved: data.filter(r => r.approval_status === 'approved').length,
                pending: data.filter(r => r.approval_status === 'pending').length,
                rejected: data.filter(r => r.approval_status === 'rejected').length,
                totalHours: data.reduce((sum, r) => sum + (parseFloat(r.time_spent) || 0), 0)
            };

            return stats;
        } catch (error) {
            console.error('[DailyReportManager] Error getting stats:', error);
            return { total: 0, approved: 0, pending: 0, rejected: 0, totalHours: 0 };
        }
    }

    /**
     * Get token from session or localStorage
     */
    getToken() {
        // Check for different token storage keys based on user type
        const adminToken = localStorage.getItem('admin_session_token') || sessionStorage.getItem('admin_session_token');
        const employeeToken = localStorage.getItem('employee_token') || sessionStorage.getItem('employee_token');
        const authToken = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        
        return adminToken || employeeToken || authToken || '';
    }

    /**
     * Get auth token (alias for getToken)
     */
    getAuthToken() {
        return this.getToken();
    }

    /**
     * Format date for display
     */
    formatDate(dateStr) {
        if (!dateStr) return '';
        try {
            return new Date(dateStr).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        } catch {
            return dateStr;
        }
    }

    /**
     * Format hours for display (alias for formatHours)
     */
    formatTime(hours) {
        return this.formatHours(hours);
    }

    /**
     * Format hours for display
     */
    formatHours(hours) {
        const h = parseFloat(hours) || 0;
        if (h === Math.floor(h)) return `${h}h`;
        return `${h.toFixed(1)}h`;
    }

    /**
     * Get headers for authenticated requests (includes X-CSRF-Token when available)
     * @param {string} contentType - optional Content-Type to include
     */
    getAuthHeaders(contentType) {
        const headers = {};
        const token = this.getToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;
        // Prefer a stored csrf token (employee token flow) or fallback to meta tag
        const storedCsrf = localStorage.getItem('csrf_token') || sessionStorage.getItem('csrf_token');
        const metaCsrf = (typeof document !== 'undefined' && document.querySelector) ? document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') : null;
        const csrf = storedCsrf || metaCsrf;
        if (csrf) headers['X-CSRF-Token'] = csrf;
        if (contentType) headers['Content-Type'] = contentType;
        return headers;
    }

    /**
     * Show notification to user
     */
    showNotification(message, type = 'info') {
        // Try to use existing notification system or create one
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            font-weight: 600;
            z-index: 9999;
            animation: slideIn 0.3s ease;
        `;

        const typeColors = {
            'success': '#48bb78',
            'error': '#f56565',
            'warning': '#ed8936',
            'info': '#4299e1'
        };

        notification.style.backgroundColor = typeColors[type] || typeColors['info'];
        notification.style.color = 'white';
        notification.textContent = message;

        document.body.appendChild(notification);

        // Auto-remove after 3 seconds
        setTimeout(() => notification.remove(), 3000);
    }

    /**
     * Get status badge HTML
     */
    getStatusBadge(status) {
        const badges = {
            'In Progress': '<span class="badge bg-info">In Progress</span>',
            'Completed': '<span class="badge bg-success">Completed</span>',
            'Blocked': '<span class="badge bg-danger">Blocked</span>'
        };
        return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
    }

    /**
     * Get approval status badge HTML
     */
    getApprovalBadge(status) {
        const badges = {
            'approved': '<span class="badge bg-success"><i class="fas fa-check-circle"></i> Approved</span>',
            'rejected': '<span class="badge bg-danger"><i class="fas fa-times-circle"></i> Rejected</span>',
            'pending': '<span class="badge bg-warning"><i class="fas fa-clock"></i> Pending</span>'
        };
        return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
    }
}

// Create global instance
const dailyReportManager = new DailyReportManager();
