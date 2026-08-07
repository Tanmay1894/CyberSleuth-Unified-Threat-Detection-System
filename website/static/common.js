// Common JavaScript for all pages

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
