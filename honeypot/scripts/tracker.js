// هذا الملف يتم تقديمه للمهاجم عند زيارته للـ Web Honeypot
(function() {
    function getFingerprint() {
        return {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screenResolution: screen.width + 'x' + screen.height,
            colorDepth: screen.colorDepth,
            canvas: getCanvasFingerprint(),
            webgl: getWebGLFingerprint(),
            fonts: getInstalledFonts()
        };
    }

    function getCanvasFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            canvas.width = 256; canvas.height = 128;
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = '#069';
            ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 4, 17);
            return canvas.toDataURL();
        } catch(e) { return 'canvas_error'; }
    }

    function getWebGLFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            var gl = canvas.getContext('webgl');
            if (!gl) return 'webgl_not_supported';
            var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) return 'webgl_no_debug';
            return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
        } catch(e) { return 'webgl_error'; }
    }

    function getInstalledFonts() {
        var fonts = ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia', 'Consolas'];
        var found = [];
        var baseFonts = ['monospace', 'sans-serif', 'serif'];
        var testString = 'mmmmmmmmmmlli';
        var h = document.getElementsByTagName('body')[0];
        var div = document.createElement('div');
        div.style.visibility = 'hidden';
        div.style.position = 'absolute';
        div.style.left = '-9999px';
        div.style.top = '-9999px';
        div.style.fontSize = '72px';
        div.innerHTML = testString;
        h.appendChild(div);
        var defaultWidth = {};
        for (var i = 0; i < baseFonts.length; i++) {
            div.style.fontFamily = baseFonts[i];
            defaultWidth[baseFonts[i]] = div.offsetWidth;
        }
        for (var f = 0; f < fonts.length; f++) {
            var font = fonts[f];
            for (var b = 0; b < baseFonts.length; b++) {
                div.style.fontFamily = font + ',' + baseFonts[b];
                if (div.offsetWidth !== defaultWidth[baseFonts[b]]) {
                    found.push(font); break;
                }
            }
        }
        h.removeChild(div);
        return found;
    }

    function sendFingerprint() {
        var data = getFingerprint();
        fetch('/api/fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).catch(function(e) { console.log('FP error', e); });
    }

    if (document.readyState === 'complete') sendFingerprint();
    else window.addEventListener('load', sendFingerprint);
})();
