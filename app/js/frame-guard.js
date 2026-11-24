// Clickjacking guard: the host cannot send `frame-ancestors` or X-Frame-Options.
// Imported first by each page entry so no app code runs inside a frame.
if (window.top !== window.self) {
    document.documentElement.style.display = 'none';
    throw new Error('This app cannot run inside a frame.');
}
