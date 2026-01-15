/**
 * Auto-Sync Integration for ApplyWizz Customer Dashboard
 * 
 * This file shows how to integrate gmail-render auto-sync into your customer dashboard.
 * When a user visits the dashboard, their emails are automatically synced in the background.
 */

// ============================================
// Configuration
// ============================================

const GMAIL_RENDER_API_URL = 'http://localhost:5000';  // Change to production URL when deployed
// const GMAIL_RENDER_API_URL = 'https://your-gmail-render.vercel.app';

// ============================================
// Auto-Sync Function
// ============================================

/**
 * Automatically sync emails for the logged-in user
 * Call this when user visits the dashboard
 * 
 * @param {string} userEmail - The logged-in user's email address
 * @returns {Promise<Object>} Sync results
 */
async function autoSyncEmails(userEmail) {
    try {
        console.log(`Starting auto-sync for ${userEmail}...`);

        const response = await fetch(`${GMAIL_RENDER_API_URL}/api/auto-sync?email=${encodeURIComponent(userEmail)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            console.log('✅ Auto-sync successful:', data);
            console.log(`📧 ${data.new_emails_count} new emails synced`);
            console.log(`🤖 ${data.processed_count} emails processed`);

            // Optionally show a toast notification
            showToast(`Synced ${data.new_emails_count} new emails`, 'success');

            return data;
        } else {
            // Handle errors
            if (data.requires_auth) {
                console.warn('⚠️ User needs to authenticate with Gmail');
                // Redirect to gmail-render login
                handleAuthRequired(userEmail);
            } else {
                console.error('❌ Auto-sync failed:', data.error);
                showToast('Email sync failed', 'error');
            }

            return data;
        }

    } catch (error) {
        console.error('❌ Auto-sync error:', error);
        showToast('Email sync error', 'error');
        return { success: false, error: error.message };
    }
}

// ============================================
// Authentication Handler
// ============================================

/**
 * Handle when user needs to authenticate with Gmail
 * Redirects to gmail-render login page
 */
function handleAuthRequired(userEmail) {
    const currentDashboardUrl = window.location.href;
    const loginUrl = `${GMAIL_RENDER_API_URL}/login?redirect_url=${encodeURIComponent(currentDashboardUrl)}`;

    // Show a message to user
    const shouldAuth = confirm('Your Gmail connection has expired. Click OK to re-authenticate.');

    if (shouldAuth) {
        window.location.href = loginUrl;
    }
}

// ============================================
// Dashboard Integration
// ============================================

/**
 * Initialize auto-sync when dashboard loads
 * This runs automatically when page loads
 */
async function initDashboard() {
    // Get logged-in user's email from your auth system
    const userEmail = getCurrentUserEmail(); // Your function to get logged-in user

    if (!userEmail) {
        console.warn('No user logged in');
        return;
    }

    // Trigger auto-sync in background
    const syncPromise = autoSyncEmails(userEmail);

    // Don't wait for sync to complete - let it run in background
    // The dashboard can load normally while emails sync

    // Optionally: Refresh job data after sync completes
    syncPromise.then((result) => {
        if (result.success && result.new_emails_count > 0) {
            // Reload job data from Supabase
            refreshJobData();
        }
    });
}

// ============================================
// Manual Sync Button (Optional)
// ============================================

/**
 * Handle manual sync button click
 * Shows loading state and updates UI
 */
async function handleManualSync() {
    const userEmail = getCurrentUserEmail();
    const syncButton = document.getElementById('sync-button');

    // Show loading state
    syncButton.disabled = true;
    syncButton.textContent = '🔄 Syncing...';

    try {
        const result = await autoSyncEmails(userEmail);

        if (result.success) {
            syncButton.textContent = `✅ Synced ${result.new_emails_count} emails`;

            // Refresh job data
            await refreshJobData();

            // Reset button after 2 seconds
            setTimeout(() => {
                syncButton.textContent = '🔄 Sync Emails';
                syncButton.disabled = false;
            }, 2000);
        } else {
            syncButton.textContent = '❌ Sync Failed';
            syncButton.disabled = false;
        }
    } catch (error) {
        syncButton.textContent = '❌ Error';
        syncButton.disabled = false;
    }
}

// ============================================
// Helper Functions
// ============================================

/**
 * Get current logged-in user's email
 * Replace this with your actual auth system
 */
function getCurrentUserEmail() {
    // Example: Get from localStorage
    return localStorage.getItem('userEmail');

    // Or from your auth context/state
    // return authContext.user.email;

    // Or from Supabase auth
    // const { data: { user } } = await supabase.auth.getUser();
    // return user?.email;
}

/**
 * Refresh job data from Supabase
 */
async function refreshJobData() {
    try {
        const userEmail = getCurrentUserEmail();

        // Fetch latest jobs from Supabase
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select('*')
            .eq('user_email', userEmail)
            .order('created_at', { ascending: false });

        if (error) throw error;

        // Update your UI with new job data
        updateJobsUI(jobs);

        console.log('✅ Job data refreshed');
    } catch (error) {
        console.error('Error refreshing job data:', error);
    }
}

/**
 * Update jobs UI with new data
 * Replace with your actual UI update logic
 */
function updateJobsUI(jobs) {
    // Example: Update next steps section
    const nextSteps = jobs.filter(job => job.status === 'next_steps');
    // ... update your UI components
}

/**
 * Show toast notification
 * Replace with your UI library (e.g., react-toastify, etc.)
 */
function showToast(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);
    // Example: toast.success(message) or toast.error(message)
}

// ============================================
// Usage Examples
// ============================================

// Example 1: Auto-sync on page load
window.addEventListener('DOMContentLoaded', initDashboard);

// Example 2: Manual sync button
// Add this to your HTML: <button id="sync-button" onclick="handleManualSync()">🔄 Sync Emails</button>

// Example 3: Periodic auto-sync (every 5 minutes)
// setInterval(() => {
//     const userEmail = getCurrentUserEmail();
//     if (userEmail) autoSyncEmails(userEmail);
// }, 5 * 60 * 1000);

// Example 4: Sync on visibility change (when user returns to tab)
// document.addEventListener('visibilitychange', () => {
//     if (!document.hidden) {
//         const userEmail = getCurrentUserEmail();
//         if (userEmail) autoSyncEmails(userEmail);
//     }
// });
