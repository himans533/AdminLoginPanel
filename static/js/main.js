// Main JavaScript for SLRD Project Management System

function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", function () {
    // Initialize all components
    initializeSidebar();
    initializeAlerts();
    initializeProgressBars();
    initializeTooltips();
    initializeFileUploads();
    initializeSearchFunctionality();
    initializeDateInputs();
    initializeFormValidation();
});

// Sidebar functionality
function initializeSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const mainContent = document.querySelector(".main-content");

    // Only initialize if sidebar exists
    if (!sidebar) return;

    // Mobile sidebar toggle
    const toggleButton = document.querySelector("[data-sidebar-toggle]");
    if (toggleButton) {
        toggleButton.addEventListener("click", function () {
            sidebar.classList.toggle("show");
        });
    }

    // Close sidebar when clicking outside on mobile
    document.addEventListener("click", function (e) {
        if (
            window.innerWidth <= 768 &&
            sidebar &&
            !sidebar.contains(e.target) &&
            !e.target.closest("[data-sidebar-toggle]")
        ) {
            sidebar.classList.remove("show");
        }
    });

    // Highlight active navigation item
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll(".sidebar-nav .nav-link");

    navLinks.forEach((link) => {
        if (link.getAttribute("href") === currentPath) {
            link.classList.add("active");
        }
    });
}

// Alert auto-dismiss
function initializeAlerts() {
    const alerts = document.querySelectorAll(".alert");

    alerts.forEach((alert) => {
        // Auto-dismiss success alerts after 5 seconds
        if (alert.classList.contains("alert-success")) {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });
}

// Animated progress bars
function initializeProgressBars() {
    const progressBars = document.querySelectorAll(".progress-bar");

    // Animate progress bars when they come into view
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                const progressBar = entry.target;
                const width = progressBar.style.width;
                progressBar.style.width = "0%";
                setTimeout(() => {
                    progressBar.style.width = width;
                }, 100);
            }
        });
    });

    progressBars.forEach((bar) => {
        observer.observe(bar);
    });
}

// Initialize tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(
        document.querySelectorAll('[data-bs-toggle="tooltip"]'),
    );
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// File upload enhancements
function initializeFileUploads() {
    const fileInputs = document.querySelectorAll('input[type="file"]');

    fileInputs.forEach((input) => {
        // Create custom file input styling
        const wrapper = document.createElement("div");
        wrapper.className = "file-input-wrapper";

        const label = document.createElement("label");
        label.className = "file-input-label";
        label.htmlFor = input.id;
        label.innerHTML = '<i class="fas fa-cloud-upload-alt"></i> Choose File';

        const fileName = document.createElement("span");
        fileName.className = "file-name";
        fileName.textContent = "No file chosen";

        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);
        wrapper.appendChild(label);
        wrapper.appendChild(fileName);

        // Update file name display
        input.addEventListener("change", function () {
            if (this.files && this.files.length > 0) {
                fileName.textContent = this.files[0].name;
                wrapper.classList.add("has-file");
            } else {
                fileName.textContent = "No file chosen";
                wrapper.classList.remove("has-file");
            }
        });

        // Drag and drop functionality
        wrapper.addEventListener("dragover", function (e) {
            e.preventDefault();
            wrapper.classList.add("drag-over");
        });

        wrapper.addEventListener("dragleave", function () {
            wrapper.classList.remove("drag-over");
        });

        wrapper.addEventListener("drop", function (e) {
            e.preventDefault();
            wrapper.classList.remove("drag-over");

            if (e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                fileName.textContent = e.dataTransfer.files[0].name;
                wrapper.classList.add("has-file");
            }
        });
    });
}

// Search functionality
function initializeSearchFunctionality() {
    const searchInput = document.querySelector(".search-box input");
    if (!searchInput) return;

    let searchTimeout;

    searchInput.addEventListener("input", function () {
        clearTimeout(searchTimeout);
        const query = this.value.toLowerCase().trim();

        if (query.length === 0) {
            // Reset all items
            document
                .querySelectorAll(
                    ".project-card, .task-card, .team-member-card",
                )
                .forEach((item) => (item.style.display = ""));
            return;
        }

        searchTimeout = setTimeout(() => {
            performSearch(query);
        }, 300);
    });

    function performSearch(query) {
        const searchableItems = document.querySelectorAll(
            ".project-card, .task-card, .team-member-card",
        );

        searchableItems.forEach((item) => {
            const text = item.textContent.toLowerCase();
            if (text.includes(query)) {
                item.style.display = "";
            } else {
                item.style.display = "none";
            }
        });
    }
}

// Date input enhancements
function initializeDateInputs() {
    const dateInputs = document.querySelectorAll('input[type="date"]');

    dateInputs.forEach((input) => {
        // Set minimum date to today for deadlines
        if (input.name === "deadline") {
            const today = new Date().toISOString().split("T")[0];
            input.min = today;
        }

        // Add date validation
        input.addEventListener("change", function () {
            const selectedDate = new Date(this.value);
            const today = new Date();
            today.setHours(0, 0, 0, 0);

            if (selectedDate < today && this.name === "deadline") {
                this.setCustomValidity("Deadline cannot be in the past");
                this.classList.add("is-invalid");
            } else {
                this.setCustomValidity("");
                this.classList.remove("is-invalid");
            }
        });
    });
}

// Form validation enhancements
function initializeFormValidation() {
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {
        form.addEventListener("submit", function (e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();

                // Focus on first invalid field
                const firstInvalid = form.querySelector(":invalid");
                if (firstInvalid) {
                    firstInvalid.focus();
                }
            }

            form.classList.add("was-validated");
        });

        // Real-time validation
        const inputs = form.querySelectorAll("input, textarea, select");
        inputs.forEach((input) => {
            input.addEventListener("blur", function () {
                if (this.checkValidity()) {
                    this.classList.remove("is-invalid");
                    this.classList.add("is-valid");
                } else {
                    this.classList.remove("is-valid");
                    this.classList.add("is-invalid");
                }
            });
        });
    });
}

// Utility functions
const Utils = {
    // Debounce function for performance
    debounce: function (func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Format file size
    formatFileSize: function (bytes) {
        if (bytes === 0) return "0 Bytes";

        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    },

    // Show loading state
    showLoading: function (element, text = "Loading...") {
        element.textContent = "";
        const icon = document.createElement("i");
        icon.className = "fas fa-spinner fa-spin";
        element.appendChild(icon);
        element.appendChild(document.createTextNode(" " + text));
        element.disabled = true;
    },

    // Hide loading state
    hideLoading: function (element, originalText) {
        element.textContent = originalText;
        element.disabled = false;
    },

    // Show notification
    showNotification: function (message, type = "info") {
        const notification = document.createElement("div");
        notification.className = `alert alert-${type} alert-dismissible fade show notification`;

        const messageText = document.createTextNode(message);
        notification.appendChild(messageText);

        const closeButton = document.createElement("button");
        closeButton.type = "button";
        closeButton.className = "btn-close";
        closeButton.setAttribute("data-bs-dismiss", "alert");
        notification.appendChild(closeButton);

        // Add to page
        const container =
            document.querySelector(".content-area") || document.body;
        container.insertBefore(notification, container.firstChild);

        // Auto-dismiss
        setTimeout(() => {
            const alert = new bootstrap.Alert(notification);
            alert.close();
        }, 5000);
    },
};

// Task filtering functionality
function filterTasks(filter) {
    const tasks = document.querySelectorAll(".task-card");
    const buttons = document.querySelectorAll(".task-filters .btn");

    // Update active button
    buttons.forEach((btn) => btn.classList.remove("active"));
    event.target.classList.add("active");

    tasks.forEach((task) => {
        const status = task.dataset.status;
        const isOverdue = task.dataset.overdue === "true";

        let show = false;

        switch (filter) {
            case "all":
                show = true;
                break;
            case "in-progress":
                show = status === "in-progress";
                break;
            case "pending":
                show = status === "pending";
                break;
            case "completed":
                show = status === "completed";
                break;
            case "overdue":
                show = isOverdue;
                break;
        }

        if (show) {
            task.style.display = "block";
            task.style.animation = "fadeIn 0.3s ease";
        } else {
            task.style.display = "none";
        }
    });
}

// Permission management functions
function selectAllPermissions() {
    const checkboxes = document.querySelectorAll(
        '.permissions-matrix input[type="checkbox"]:not([disabled])',
    );
    checkboxes.forEach((checkbox) => {
        checkbox.checked = true;
    });

    Utils.showNotification("All permissions selected", "success");
}

function clearAllPermissions() {
    const checkboxes = document.querySelectorAll(
        '.permissions-matrix input[type="checkbox"]:not([disabled])',
    );
    checkboxes.forEach((checkbox) => {
        checkbox.checked = false;
    });

    Utils.showNotification("All permissions cleared", "info");
}

// Real-time updates for progress
function updateProgress() {
    fetch("/api/progress-update")
        .then((response) => response.json())
        .then((data) => {
            // Update progress bars and statistics
            document
                .querySelectorAll("[data-project-id]")
                .forEach((element) => {
                    const projectId = element.dataset.projectId;
                    if (data.projects[projectId]) {
                        const progress = data.projects[projectId].progress;
                        const progressBar =
                            element.querySelector(".progress-bar");
                        if (progressBar) {
                            progressBar.style.width = progress + "%";
                        }
                    }
                });
        })
        .catch((error) => console.error("Error updating progress:", error));
}

// Dashboard modal functionality
function showDetailModal(modalType) {
    // Create modal if it doesn't exist
    let modal = document.getElementById("detailModal");
    if (!modal) {
        modal = createDetailModal();
        document.body.appendChild(modal);
    }

    // Set modal title and show loading
    const modalTitle = document.getElementById("detailModalLabel");
    const modalBody = document.getElementById("detailModalBody");

    modalTitle.textContent = getModalTitle(modalType);
    modalBody.innerHTML =
        '<div class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>';

    // Show modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    // Fetch data and populate modal
    fetch(`/api/dashboard/${modalType}`)
        .then((response) => response.json())
        .then((data) => {
            modalBody.innerHTML = generateModalContent(modalType, data);
        })
        .catch((error) => {
            modalBody.innerHTML =
                '<div class="alert alert-danger">Error loading data</div>';
            console.error("Error:", error);
        });
}

function createDetailModal() {
    const modal = document.createElement("div");
    modal.className = "modal fade";
    modal.id = "detailModal";
    modal.tabIndex = -1;
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="detailModalLabel">Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="detailModalBody">
                    Loading...
                </div>
            </div>
        </div>
    `;
    return modal;
}

function getModalTitle(modalType) {
    const titles = {
        active_tasks: "Active Tasks",
        completed_tasks: "Completed Tasks",
        overdue_tasks: "Overdue Tasks",
        pending_approvals: "Pending Approvals",
        active_projects: "Active Projects",
        task_outcomes: "Task Outcomes",
    };
    return titles[modalType] || "Details";
}

function generateModalContent(modalType, data) {
    if (modalType === "active_projects" && data.projects) {
        return generateProjectsList(data.projects);
    } else if (modalType === "task_outcomes" && data.outcomes) {
        return generateOutcomesList(data.outcomes);
    } else if (modalType === "pending_approvals" && data.items) {
        return generateApprovalsList(data.items);
    } else if (data.tasks) {
        return generateTasksList(data.tasks, modalType);
    }
    return '<div class="text-center text-muted">No data found</div>';
}

function generateTasksList(tasks, modalType) {
    if (tasks.length === 0) {
        return '<div class="text-center text-muted">No tasks found</div>';
    }

    let html = '<div class="list-group">';
    tasks.forEach((task) => {
        html += `
            <div class="list-group-item d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">
                        <a href="/tasks/${encodeURIComponent(task.id)}" style="color: purple; font-weight: bold;">${escapeHtml(task.title)}</a>
                    </h6>
                    <p class="mb-1 text-muted">📋 Project: <span style="color: blue; font-weight: bold;">${escapeHtml(task.project_title)}</span></p>
                    <small>🟦 Created by: <span style="color: blue; font-weight: bold;">${escapeHtml(task.created_by)}</span> | 
                    🟩 Created: <span style="color: green; font-weight: bold;">${escapeHtml(task.created_at)}</span>
                    ${task.deadline ? `| 🟥 Due: <span style="color: red; font-weight: bold;">${escapeHtml(task.deadline)}</span>` : ""}
                    ${task.assigned_user ? `| 👤 Assigned: <span style="color: darkgreen; font-weight: bold;">${escapeHtml(task.assigned_user)}</span>` : ""}</small>
                </div>
                <div class="d-flex align-items-center">
                    <span class="badge bg-primary me-2">⚡ ${escapeHtml(task.priority)}</span>
                    <span class="badge bg-secondary me-2">📊 ${escapeHtml(task.status)}</span>
                    ${
                        modalType === "active_tasks"
                            ? `
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                ⋮
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="#" onclick="showReassignModal(${encodeURIComponent(task.id)})">Reassign Task</a></li>
                            </ul>
                        </div>
                    `
                            : ""
                    }
                </div>
            </div>
        `;
    });
    html += "</div>";
    return html;
}

function generateProjectsList(projects) {
    if (projects.length === 0) {
        return '<div class="text-center text-muted">No projects found</div>';
    }

    let html = '<div class="list-group">';
    projects.forEach((project) => {
        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">
                            <a href="/projects/${encodeURIComponent(project.id)}" style="color: purple; font-weight: bold;">${escapeHtml(project.title)}</a>
                        </h6>
                        <p class="mb-1">${escapeHtml(project.description) || "No description"}</p>
                        <small>🟦 Created by: <span style="color: blue; font-weight: bold;">${escapeHtml(project.created_by)}</span> | 
                        🟩 Created: <span style="color: green; font-weight: bold;">${escapeHtml(project.created_at)}</span>
                        ${project.deadline ? `| 🟥 Deadline: <span style="color: red; font-weight: bold;">${escapeHtml(project.deadline)}</span>` : ""}</small>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-info">📊 ${escapeHtml(project.status)}</span>
                        <div class="mt-1">
                            <small>🟧 Progress: <span style="color: orange; font-weight: bold;">${escapeHtml(project.progress)}%</span></small>
                        </div>
                        <div class="progress mt-1" style="width: 100px; height: 6px;">
                            <div class="progress-bar" style="width: ${escapeHtml(project.progress)}%"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    html += "</div>";
    return html;
}

function generateOutcomesList(outcomes) {
    if (outcomes.length === 0) {
        return '<div class="text-center text-muted">No task outcomes found</div>';
    }

    // Group outcomes by task
    const groupedOutcomes = {};
    outcomes.forEach((outcome) => {
        if (!groupedOutcomes[outcome.task_id]) {
            groupedOutcomes[outcome.task_id] = {
                task_title: outcome.task_title,
                task_id: outcome.task_id,
                outcomes: [],
            };
        }
        groupedOutcomes[outcome.task_id].outcomes.push(outcome);
    });

    let html = '<div class="list-group">';
    Object.keys(groupedOutcomes).forEach((taskId) => {
        const task = groupedOutcomes[taskId];
        const completedOutcomes = task.outcomes.filter(
            (o) => o.status === "Completed",
        ).length;
        const totalOutcomes = task.outcomes.length;

        html += `
            <div class="list-group-item d-flex justify-content-between align-items-center">
                <div class="flex-grow-1">
                    <h6 class="mb-1">
                        <a href="/tasks/${task.task_id}" style="color: purple; font-weight: bold;">${task.task_title}</a>
                    </h6>
                    <small class="text-muted">🎯 ${completedOutcomes}/${totalOutcomes} outcomes completed</small>
                </div>
                <div class="d-flex align-items-center">
                    <span class="badge bg-info me-2">${totalOutcomes} outcomes</span>
                    <button class="btn btn-sm btn-outline-primary" onclick="showTaskOutcomes(${task.task_id}, '${task.task_title}')">
                        Show More
                    </button>
                </div>
            </div>
        `;
    });
    html += "</div>";
    return html;
}

// Function to show specific task outcomes
function showTaskOutcomes(taskId, taskTitle) {
    // Create a new modal for task-specific outcomes
    let modal = document.getElementById("taskOutcomesModal");
    if (!modal) {
        modal = createTaskOutcomesModal();
        document.body.appendChild(modal);
    }

    const modalTitle = document.getElementById("taskOutcomesModalLabel");
    const modalBody = document.getElementById("taskOutcomesModalBody");

    modalTitle.innerHTML = `📋 Task Outcomes: <span style="color: blue; font-weight: bold;">${taskTitle}</span>`;
    modalBody.innerHTML =
        '<div class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>';

    // Show modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    // Fetch task-specific outcomes
    fetch(`/api/task-outcomes/${taskId}`)
        .then((response) => response.json())
        .then((data) => {
            modalBody.innerHTML = generateTaskSpecificOutcomes(
                data.outcomes,
                taskId,
            );
        })
        .catch((error) => {
            modalBody.innerHTML =
                '<div class="alert alert-danger">Error loading task outcomes</div>';
            console.error("Error:", error);
        });
}

function createTaskOutcomesModal() {
    const modal = document.createElement("div");
    modal.className = "modal fade";
    modal.id = "taskOutcomesModal";
    modal.tabIndex = -1;
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="taskOutcomesModalLabel">Task Outcomes</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="taskOutcomesModalBody">
                    Loading...
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" onclick="addNewOutcome()">Add New Outcome</button>
                </div>
            </div>
        </div>
    `;
    return modal;
}

function generateTaskSpecificOutcomes(outcomes, taskId) {
    if (outcomes.length === 0) {
        return `
            <div class="text-center text-muted">
                <p>No outcomes found for this task</p>
                <button class="btn btn-primary" onclick="addNewOutcome(${taskId})">Add First Outcome</button>
            </div>
        `;
    }

    let html = '<div class="list-group">';
    outcomes.forEach((outcome) => {
        const statusColor =
            outcome.status === "Completed" ? "success" : "warning";
        const statusIcon = outcome.status === "Completed" ? "✅" : "⏳";

        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h6 class="mb-1">${outcome.title}</h6>
                        <p class="mb-1 text-muted">${outcome.description || "No description"}</p>
                        <small>🟦 Created by: <span style="color: blue; font-weight: bold;">${outcome.created_by}</span>
                        ${outcome.deadline ? `| 🟥 Due: <span style="color: red; font-weight: bold;">${outcome.deadline}</span>` : ""}</small>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-${statusColor}">${statusIcon} ${outcome.status}</span>
                        ${
                            outcome.status === "Pending"
                                ? `
                            <div class="mt-2">
                                <button class="btn btn-sm btn-success" onclick="completeOutcome(${outcome.id})">
                                    Mark Complete
                                </button>
                            </div>
                        `
                                : ""
                        }
                    </div>
                </div>
            </div>
        `;
    });
    html += "</div>";
    return html;
}

function completeOutcome(outcomeId) {
    fetch(`/outcomes/${outcomeId}/complete`, {
        method: "POST",
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                Utils.showNotification("Outcome marked as complete", "success");
                // Refresh the task outcomes modal
                const currentTaskId = document
                    .querySelector("#taskOutcomesModalLabel")
                    .textContent.match(/Task Outcomes: (.+)/)?.[1];
                if (currentTaskId) {
                    showTaskOutcomes(currentTaskId);
                }
            } else {
                Utils.showNotification(
                    data.error || "Failed to complete outcome",
                    "error",
                );
            }
        })
        .catch((error) => {
            Utils.showNotification("Error completing outcome", "error");
            console.error("Error:", error);
        });
}

function generateApprovalsList(items) {
    if (items.length === 0) {
        return '<div class="text-center text-muted">No pending approvals found</div>';
    }

    let html = '<div class="list-group">';
    items.forEach((item) => {
        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">
                            <a href="/${item.type}s/${item.id}" style="color: purple; font-weight: bold;">${item.title}</a>
                        </h6>
                        ${item.project_title ? `<p class="mb-1 text-muted">📋 Project: <span style="color: blue; font-weight: bold;">${item.project_title}</span></p>` : ""}
                        <small>🟦 Marked complete by: <span style="color: blue; font-weight: bold;">${item.marked_by}</span> | 
                        🟩 Marked at: <span style="color: green; font-weight: bold;">${item.marked_at}</span></small>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-warning">⚡ ${item.priority}</span>
                        <div class="mt-2">
                            <button class="btn btn-sm btn-success me-1" onclick="approveItem('${item.type}', ${item.id})">
                                ✅ Approve
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="rejectItem('${item.type}', ${item.id})">
                                ❌ Reject
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    html += "</div>";
    return html;
}

// Task reassignment functionality
function showReassignModal(taskId) {
    fetch("/api/team-members")
        .then((response) => response.json())
        .then((data) => {
            const modal = createReassignModal(taskId, data.team_members);
            document.body.appendChild(modal);
            const bsModal = new bootstrap.Modal(modal);
            bsModal.show();

            // Remove modal from DOM when hidden
            modal.addEventListener("hidden.bs.modal", function () {
                modal.remove();
            });
        })
        .catch((error) => {
            Utils.showNotification("Error loading team members", "error");
            console.error("Error:", error);
        });
}

function createReassignModal(taskId, teamMembers) {
    const modal = document.createElement("div");
    modal.className = "modal fade";
    modal.id = "reassignModal";
    modal.tabIndex = -1;

    let options = "";
    teamMembers.forEach((member) => {
        options += `<option value="${member.id}">${member.username} (${member.role})</option>`;
    });

    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reassign Task</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="reassignForm">
                        <div class="mb-3">
                            <label for="assignedUser" class="form-label">👤 Assign to:</label>
                            <select class="form-select" id="assignedUser" required>
                                <option value="">Select team member...</option>
                                ${options}
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="reassignTask(${taskId})">Reassign</button>
                </div>
            </div>
        </div>
    `;
    return modal;
}

function reassignTask(taskId) {
    const assignedUserId = document.getElementById("assignedUser").value;
    if (!assignedUserId) {
        Utils.showNotification("Please select a team member", "error");
        return;
    }

    fetch(`/tasks/${taskId}/reassign`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `assigned_to_id=${assignedUserId}`,
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                Utils.showNotification(
                    "Task reassigned successfully",
                    "success",
                );
                const modal = bootstrap.Modal.getInstance(
                    document.getElementById("reassignModal"),
                );
                modal.hide();
                // Refresh the detail modal if it's open
                const detailModal = document.getElementById("detailModal");
                if (detailModal && detailModal.classList.contains("show")) {
                    showDetailModal("active_tasks");
                }
            } else {
                Utils.showNotification(
                    data.error || "Failed to reassign task",
                    "error",
                );
            }
        })
        .catch((error) => {
            Utils.showNotification("Error reassigning task", "error");
            console.error("Error:", error);
        });
}

// Approval functions
function approveItem(itemType, itemId) {
    fetch(`/api/approve/${itemType}/${itemId}`, {
        method: "POST",
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                Utils.showNotification(
                    `${itemType} approved successfully`,
                    "success",
                );
                showDetailModal("pending_approvals"); // Refresh the modal
            } else {
                Utils.showNotification(
                    data.error || "Failed to approve",
                    "error",
                );
            }
        })
        .catch((error) => {
            Utils.showNotification("Error approving item", "error");
            console.error("Error:", error);
        });
}

function rejectItem(itemType, itemId) {
    fetch(`/api/reject/${itemType}/${itemId}`, {
        method: "POST",
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                Utils.showNotification(`${itemType} rejected`, "success");
                showDetailModal("pending_approvals"); // Refresh the modal
            } else {
                Utils.showNotification(
                    data.error || "Failed to reject",
                    "error",
                );
            }
        })
        .catch((error) => {
            Utils.showNotification("Error rejecting item", "error");
            console.error("Error:", error);
        });
}

// Auto-save functionality for forms
function initializeAutoSave() {
    const forms = document.querySelectorAll("[data-autosave]");

    forms.forEach((form) => {
        const inputs = form.querySelectorAll("input, textarea, select");

        inputs.forEach((input) => {
            input.addEventListener(
                "input",
                Utils.debounce(() => {
                    saveFormData(form);
                }, 2000),
            );
        });
    });
}

function saveFormData(form) {
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);

    // Save to localStorage
    localStorage.setItem(`form_${form.id}`, JSON.stringify(data));

    // Show save indicator
    const saveIndicator = document.createElement("span");
    saveIndicator.className = "save-indicator";
    saveIndicator.innerHTML = '<i class="fas fa-check"></i> Saved';

    form.appendChild(saveIndicator);
    setTimeout(() => saveIndicator.remove(), 2000);
}

// Keyboard shortcuts
document.addEventListener("keydown", function (e) {
    // Ctrl/Cmd + K for search
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        const searchInput = document.querySelector(".search-box input");
        if (searchInput) {
            searchInput.focus();
        }
    }

    // Escape to close modals/dropdowns
    if (e.key === "Escape") {
        const openDropdowns = document.querySelectorAll(".dropdown-menu.show");
        openDropdowns.forEach((dropdown) => {
            const toggle = dropdown.previousElementSibling;
            if (toggle) {
                bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
            }
        });
    }
});

// Performance monitoring
function monitorPerformance() {
    // Monitor page load time
    window.addEventListener("load", function () {
        const loadTime =
            performance.timing.loadEventEnd -
            performance.timing.navigationStart;
        console.log(`Page loaded in ${loadTime}ms`);

        // Track slow pages
        if (loadTime > 3000) {
            console.warn("Page load time is slow:", loadTime + "ms");
        }
    });

    // Monitor memory usage
    if ("memory" in performance) {
        setInterval(() => {
            const memory = performance.memory;
            if (memory.usedJSHeapSize > 50 * 1024 * 1024) {
                // 50MB
                console.warn(
                    "High memory usage detected:",
                    memory.usedJSHeapSize,
                );
            }
        }, 30000);
    }
}

// Initialize performance monitoring in development
if (window.location.hostname === "localhost") {
    monitorPerformance();
}

// Export utils for global access
window.ProjectManagement = {
    Utils,
    filterTasks,
    selectAllPermissions,
    clearAllPermissions,
    updateProgress,
};

// Add CSS animations
const style = document.createElement("style");
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    @keyframes slideIn {
        from { transform: translateX(-100%); }
        to { transform: translateX(0); }
    }

    .notification {
        animation: slideIn 0.3s ease;
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
    }

    .file-input-wrapper {
        position: relative;
        border: 2px dashed #e2e8f0;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
    }

    .file-input-wrapper.drag-over {
        border-color: #4a90b8;
        background-color: #f0f8ff;
    }

    .file-input-wrapper.has-file {
        border-color: #3db570;
        background-color: #f0fff4;
    }

    .file-input-wrapper input[type="file"] {
        position: absolute;
        opacity: 0;
        width: 100%;
        height: 100%;
        cursor: pointer;
    }

    .file-input-label {
        display: block;
        color: #4a90b8;
        font-weight: 500;
        cursor: pointer;
        margin-bottom: 8px;
    }

    .file-name {
        display: block;
        color: #64748b;
        font-size: 0.9rem;
    }

    .save-indicator {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #3db570;
        color: white;
        padding: 8px 16px;
        border-radius: 4px;
        font-size: 0.9rem;
        animation: slideIn 0.3s ease;
    }
`;
document.head.appendChild(style);
