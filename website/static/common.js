// Common JavaScript for all pages

// Initialize sidebar toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    initializeSidebar();
});

function initializeSidebar() {
    if (document.querySelector('script[src*="sidebar-manager.js"]')) {
        return;
    }

    const toggleBtn = document.getElementById('toggleSidebar');
    const sidebar = document.getElementById('sidebar');

    if (!toggleBtn || !sidebar) {
        return;
    }

    // Check localStorage for saved state
    const savedState = localStorage.getItem('sidebarCollapsed');
    if (savedState === 'true') {
        sidebar.classList.add('collapsed');
    }

    toggleBtn.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('sidebarCollapsed', isCollapsed);
    });
}

// Utility function to format timestamps
function formatTime() {
    const now = new Date();
    return now.toLocaleTimeString('en-US', { hour12: false });
}

// Utility function to format date and time
function formatDateTime() {
    const now = new Date();
    return now.toLocaleString('en-US', { 
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}
