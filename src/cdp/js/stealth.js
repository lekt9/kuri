// Stealth script — injected via Page.addScriptToEvaluateOnNewDocument
// Hides automation indicators from bot detection.
//
// Source of truth: this file. The top-level js/stealth.js is a historical
// duplicate (kept only because the readme references that path).
// `@embedFile("js/stealth.js")` in src/cdp/stealth.zig resolves here.

(function () {
    'use strict';

    // ── 0. toString proxy ───────────────────────────────────────────────────
    // The single most important patch. When we override a getter via
    // Object.defineProperty, the resulting function's `.toString()` returns
    // "function () { return false; }" — a dead giveaway. Real native getters
    // return "function get webdriver() { [native code] }". This proxy makes
    // every patched getter/function report itself as native.
    const nativeToStringStr = Function.prototype.toString.toString();
    const fakeToStringMap = new WeakMap();

    function makeNative(fn, nativeName) {
        const nativeStr = 'function ' + (nativeName || fn.name || '') +
            '() { [native code] }';
        fakeToStringMap.set(fn, nativeStr);
        return fn;
    }

    const origToString = Function.prototype.toString;
    Function.prototype.toString = new Proxy(origToString, {
        apply(target, thisArg, args) {
            if (fakeToStringMap.has(thisArg)) {
                return fakeToStringMap.get(thisArg);
            }
            return Reflect.apply(target, thisArg, args);
        },
    });
    // Make our own toString proxy report as native too.
    fakeToStringMap.set(Function.prototype.toString, nativeToStringStr);

    function defineNativeGetter(obj, prop, getter, nativeName) {
        const wrapped = makeNative(getter, 'get ' + (nativeName || prop));
        try {
            Object.defineProperty(obj, prop, {
                get: wrapped,
                configurable: true,
                enumerable: true,
            });
        } catch (e) { /* prop locked, skip */ }
    }

    // ── 1. navigator.webdriver ──────────────────────────────────────────────
    defineNativeGetter(Navigator.prototype, 'webdriver', () => false, 'webdriver');

    // ── 2. navigator.plugins — fake non-empty plugins array ─────────────────
    defineNativeGetter(Navigator.prototype, 'plugins', () => {
        const plugins = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        ];
        plugins.length = 5;
        plugins.item = makeNative((i) => plugins[i] || null, 'item');
        plugins.namedItem = makeNative((n) => plugins.find(p => p.name === n) || null, 'namedItem');
        plugins.refresh = makeNative(() => {}, 'refresh');
        return plugins;
    }, 'plugins');

    // ── 3. navigator.languages ─────────────────────────────────────────────
    defineNativeGetter(Navigator.prototype, 'languages', () => ['en-US', 'en'], 'languages');

    // ── 4. window.chrome — must exist with .app, .runtime, .csi, .loadTimes ─
    if (!window.chrome) {
        window.chrome = {};
    }
    if (!window.chrome.app) {
        window.chrome.app = {
            isInstalled: false,
            InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
            RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
            getDetails: makeNative(() => null, 'getDetails'),
            getIsInstalled: makeNative(() => false, 'getIsInstalled'),
        };
    }
    if (!window.chrome.runtime) {
        window.chrome.runtime = {
            OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
            OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
            PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
            PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
            PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
            RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' },
            connect: makeNative(() => {}, 'connect'),
            sendMessage: makeNative(() => {}, 'sendMessage'),
        };
    }
    if (!window.chrome.csi) {
        window.chrome.csi = makeNative(() => ({
            startE: Date.now(),
            onloadT: Date.now(),
            pageT: Math.random() * 1000 + 100,
            tpiT: 0,
        }), 'csi');
    }
    if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = makeNative(() => ({
            commitLoadTime: Date.now() / 1000,
            connectionInfo: 'h2',
            finishDocumentLoadTime: Date.now() / 1000,
            finishLoadTime: Date.now() / 1000,
            firstPaintAfterLoadTime: 0,
            firstPaintTime: Date.now() / 1000,
            navigationType: 'Other',
            npnNegotiatedProtocol: 'h2',
            requestTime: Date.now() / 1000 - 0.3,
            startLoadTime: Date.now() / 1000 - 0.5,
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: true,
            wasNpnNegotiated: true,
        }), 'loadTimes');
    }

    // ── 5. Permissions API — Notification.permission leak ───────────────────
    // Headless Chrome returns "denied" for Notification.permission while the
    // permissions.query API returns "default" — that mismatch is a tell.
    try {
        const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
        if (originalQuery) {
            window.navigator.permissions.query = makeNative((parameters) => {
                if (parameters && parameters.name === 'notifications') {
                    return Promise.resolve({ state: 'default', onchange: null });
                }
                return originalQuery.call(window.navigator.permissions, parameters);
            }, 'query');
        }
    } catch (e) {}

    // ── 6. iframe contentWindow descriptor preservation ─────────────────────
    try {
        const elementDescriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (elementDescriptor && elementDescriptor.get) {
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                get: makeNative(function () { return elementDescriptor.get.call(this); }, 'get contentWindow'),
                configurable: true,
                enumerable: true,
            });
        }
    } catch (e) {}

    // ── 7. WebGL renderer spoofing ─────────────────────────────────────────
    try {
        const wrapGetParameter = (proto) => {
            const orig = proto.getParameter;
            proto.getParameter = makeNative(function (param) {
                if (param === 0x1F01) return 'Intel Inc.';                 // VENDOR
                if (param === 0x1F00) return 'Intel Iris OpenGL Engine';   // RENDERER
                if (param === 0x9245) return 'Intel Inc.';                 // UNMASKED_VENDOR_WEBGL
                if (param === 0x9246) return 'Intel Iris OpenGL Engine';   // UNMASKED_RENDERER_WEBGL
                return orig.call(this, param);
            }, 'getParameter');
        };
        wrapGetParameter(WebGLRenderingContext.prototype);
        if (typeof WebGL2RenderingContext !== 'undefined') {
            wrapGetParameter(WebGL2RenderingContext.prototype);
        }
    } catch (e) {}

    // ── 8. Canvas fingerprint noise ────────────────────────────────────────
    try {
        const shiftPixels = (canvas) => {
            const ctx = canvas.getContext('2d');
            if (!ctx || !canvas.width || !canvas.height) return;
            const shift = (Math.random() - 0.5) * 0.01;
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + shift));
            }
            ctx.putImageData(imageData, 0, 0);
        };
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = makeNative(function () {
            try { shiftPixels(this); } catch (e) {}
            return origToDataURL.apply(this, arguments);
        }, 'toDataURL');
        const origToBlob = HTMLCanvasElement.prototype.toBlob;
        HTMLCanvasElement.prototype.toBlob = makeNative(function () {
            try { shiftPixels(this); } catch (e) {}
            return origToBlob.apply(this, arguments);
        }, 'toBlob');
    } catch (e) {}

    // ── 9. AudioContext fingerprint noise ──────────────────────────────────
    try {
        if (typeof AudioContext !== 'undefined') {
            const origCreateOscillator = AudioContext.prototype.createOscillator;
            AudioContext.prototype.createOscillator = makeNative(function () {
                const oscillator = origCreateOscillator.apply(this, arguments);
                const origStart = oscillator.start.bind(oscillator);
                oscillator.start = makeNative(function (when) {
                    const noise = Math.random() * 1e-7;
                    return origStart((when || 0) + noise);
                }, 'start');
                return oscillator;
            }, 'createOscillator');
        }
    } catch (e) {}

    // ── 10. Hardware concurrency / device memory / connection ──────────────
    defineNativeGetter(Navigator.prototype, 'hardwareConcurrency', () => 8, 'hardwareConcurrency');
    defineNativeGetter(Navigator.prototype, 'deviceMemory', () => 8, 'deviceMemory');
    try {
        if (!navigator.connection) {
            defineNativeGetter(Navigator.prototype, 'connection', () => ({
                effectiveType: '4g',
                rtt: 50,
                downlink: 10,
                saveData: false,
                onchange: null,
            }), 'connection');
        }
    } catch (e) {}

    // ── 11. mediaDevices.enumerateDevices — headless returns [] which is a tell
    try {
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            const orig = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
            navigator.mediaDevices.enumerateDevices = makeNative(async function () {
                const devices = await orig();
                if (devices.length > 0) return devices;
                // Return a plausible default set
                return [
                    { kind: 'audioinput',  deviceId: 'default', groupId: 'default', label: '' },
                    { kind: 'videoinput',  deviceId: 'default', groupId: 'default', label: '' },
                    { kind: 'audiooutput', deviceId: 'default', groupId: 'default', label: '' },
                ];
            }, 'enumerateDevices');
        }
    } catch (e) {}

    // ── 12. window.outerWidth / outerHeight — headless reports 0 ───────────
    try {
        if (window.outerWidth === 0 || window.outerHeight === 0) {
            Object.defineProperty(window, 'outerWidth', {
                get: makeNative(() => window.innerWidth, 'get outerWidth'),
                configurable: true,
            });
            Object.defineProperty(window, 'outerHeight', {
                get: makeNative(() => window.innerHeight, 'get outerHeight'),
                configurable: true,
            });
        }
    } catch (e) {}

    // ── 13. CDP detection via console.debug / Error stack ──────────────────
    // Some detectors call console.debug(new Error()) and check if the stack
    // got truncated by DevTools formatting. Best-effort patch — leave
    // console alone but make Error stacks normal.
    try {
        const origStackTraceLimit = Error.stackTraceLimit;
        if (origStackTraceLimit < 10) Error.stackTraceLimit = 10;
    } catch (e) {}

})();
