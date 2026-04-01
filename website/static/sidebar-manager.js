// 🚀 UNIFIED SIDEBAR MANAGER - Include in ALL pages
class UnifiedSidebar {
    constructor() {
        this.isCollapsed = false;
        this.init();
    }

    init() {
        this.sidebar = document.getElementById('sidebar');
        this.toggleBtn = document.querySelector('#sidebarToggle, .sidebar-toggle, #toggleSidebar, .toggle-btn');
        this.overlay = document.querySelector('.mobile-overlay');
        this.links = document.querySelectorAll('#sidebar .nav-link[data-page]');

        if (!this.sidebar) return;

        this.restoreState();
        this.bindEvents();
        this.setActivePage();
    }

    bindEvents() {
        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', () => this.toggle());
        }

        this.links.forEach(link => {
            link.addEventListener('click', () => {
                this.setActiveLink(link);
                this.saveState();
            });
        });

        if (this.overlay) {
            this.overlay.addEventListener('click', () => this.closeMobile());
        }

        window.addEventListener('resize', () => this.updateLayout());
    }

    toggle() {
        this.isCollapsed = !this.isCollapsed;
        this.sidebar.classList.toggle('collapsed', this.isCollapsed);
        this.sidebar.classList.toggle('mobile-open', false);
        this.updateLayout();
        this.saveState();
    }

    setActivePage() {
        const path = window.location.pathname.split('/').pop() || 'index.html';
        const pageName = path.replace('.html', '');

        this.links.forEach(link => {
            const dataPage = link.dataset.page;
            if ((dataPage === pageName) || (dataPage === 'index' && pageName === '') || (dataPage === 'network' && pageName === 'network_frontend')) {
                this.setActiveLink(link);
            }
        });
    }

    setActiveLink(link) {
        document.querySelectorAll('#sidebar .nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
    }

    updateLayout() {
        const content = document.querySelector('.main-content, .page-content');
        if (content && window.innerWidth > 768) {
            content.style.marginLeft = this.isCollapsed ? '72px' : '260px';
        }
    }

    saveState() {
        sessionStorage.setItem('cyberSleuthSidebar', JSON.stringify({
            collapsed: this.isCollapsed,
            activePage: document.querySelector('#sidebar .nav-link.active')?.dataset.page || 'index'
        }));
    }

    restoreState() {
        try {
            const state = JSON.parse(sessionStorage.getItem('cyberSleuthSidebar') || '{}');
            this.isCollapsed = state.collapsed || false;

            if (this.sidebar) {
                this.sidebar.classList.toggle('collapsed', this.isCollapsed);
                this.updateLayout();
            }
        } catch (e) {}
    }

    closeMobile() {
        if (this.sidebar) {
            this.sidebar.classList.remove('mobile-open');
        }
    }
}

// Global init
document.addEventListener('DOMContentLoaded', () => {
    window.unifiedSidebar = new UnifiedSidebar();
});
