const NOTIFICATIONS_PROMPTED_FLAG = 'poolstellar_notifications_prompted';
const META_CACHE = 'poolstellar-meta';
const LAST_VISIT_URL = '/last-visit';

export function hasNotificationSupport() {
    return typeof Notification !== 'undefined' && 'serviceWorker' in navigator;
}

export function getNotificationsPrompted() {
    try {
        return window.localStorage.getItem(NOTIFICATIONS_PROMPTED_FLAG) === '1';
    } catch {
        return false;
    }
}

export function setNotificationsPrompted() {
    try {
        window.localStorage.setItem(NOTIFICATIONS_PROMPTED_FLAG, '1');
    } catch (e) {
        console.error('[PushNotifications] setNotificationsPrompted failed:', e);
    }
}

export async function requestNotificationPermission() {
    if (!hasNotificationSupport()) return 'unsupported';
    try {
        return await Notification.requestPermission();
    } catch (e) {
        console.debug('[PushNotifications] requestPermission failed:', e);
        return 'denied';
    }
}

export async function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    try {
        const reg = await navigator.serviceWorker.register('/sw.js');
        if ('periodicSync' in reg) {
            try {
                const status = await navigator.permissions.query({ name: 'periodic-background-sync' });
                if (status.state === 'granted') {
                    await reg.periodicSync.register('check-last-visit', {
                        minInterval: 24 * 60 * 60 * 1000,
                    });
                }
            } catch (e) {
                console.debug('[PushNotifications] periodicSync registration failed:', e);
            }
        }
    } catch (e) {
        console.debug('[PushNotifications] SW registration failed:', e);
    }
}

export async function updateLastVisit() {
    try {
        const cache = await caches.open(META_CACHE);
        await cache.put(LAST_VISIT_URL, new Response(String(Date.now())));
    } catch (e) {
        console.debug('[PushNotifications] updateLastVisit failed:', e);
    }
}
