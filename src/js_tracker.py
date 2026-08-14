"""
هذا الملف يولد كود JavaScript يتم حقنه في صفحة الويب الوهمية
لجمع بصمة المتصفح (Canvas, Fonts, Timezone, WebGL)
"""
import json

class JSTracker:
    @staticmethod
    def generate_tracker_code():
        return """
        <script>
        (function() {
            // دالة جمع البصمة
            function getFingerprint() {
                return {
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    language: navigator.language,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    screenResolution: screen.width + 'x' + screen.height,
                    colorDepth: screen.colorDepth,
                    cookiesEnabled: navigator.cookieEnabled,
                    doNotTrack: navigator.doNotTrack,
                    canvas: getCanvasFingerprint(),
                    webgl: getWebGLFingerprint(),
                    fonts: getInstalledFonts(),
                    audio: getAudioFingerprint()
                };
            }

            function getCanvasFingerprint() {
                try {
                    var canvas = document.createElement('canvas');
                    canvas.width = 256;
                    canvas.height = 128;
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
                var fonts = ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia', 'Comic Sans MS', 'Trebuchet MS', 'Impact', 'Consolas', 'Monaco'];
                var found = [];
                var baseFonts = ['monospace', 'sans-serif', 'serif'];
                var testString = 'mmmmmmmmmmlli';
                var testSize = '72px';
                var h = document.getElementsByTagName('body')[0];
                var div = document.createElement('div');
                div.style.visibility = 'hidden';
                div.style.position = 'absolute';
                div.style.left = '-9999px';
                div.style.top = '-9999px';
                div.style.fontSize = testSize;
                div.style.textRendering = 'geometricPrecision';
                div.innerHTML = testString;
                h.appendChild(div);
                var defaultWidth = {};
                var defaultHeight = {};
                for (var i = 0; i < baseFonts.length; i++) {
                    div.style.fontFamily = baseFonts[i];
                    defaultWidth[baseFonts[i]] = div.offsetWidth;
                    defaultHeight[baseFonts[i]] = div.offsetHeight;
                }
                for (var f = 0; f < fonts.length; f++) {
                    var font = fonts[f];
                    var detected = false;
                    for (var b = 0; b < baseFonts.length; b++) {
                        div.style.fontFamily = font + ',' + baseFonts[b];
                        if (div.offsetWidth !== defaultWidth[baseFonts[b]] || div.offsetHeight !== defaultHeight[baseFonts[b]]) {
                            detected = true;
                            break;
                        }
                    }
                    if (detected) found.push(font);
                }
                h.removeChild(div);
                return found;
            }

            function getAudioFingerprint() {
                try {
                    var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                    var oscillator = audioCtx.createOscillator();
                    var analyser = audioCtx.createAnalyser();
                    oscillator.connect(analyser);
                    analyser.connect(audioCtx.destination);
                    oscillator.start(0);
                    var data = new Uint8Array(analyser.frequencyBinCount);
                    analyser.getByteFrequencyData(data);
                    oscillator.stop(0);
                    audioCtx.close();
                    return Array.from(data).join(',');
                } catch(e) { return 'audio_error'; }
            }

            // إرسال البيانات إلى الخادم الوهمي
            function sendFingerprint() {
                var data = getFingerprint();
                fetch('/api/fingerprint', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                }).catch(function(e) { console.log('Fingerprint send error', e); });
            }

            // التنفيذ بعد تحميل الصفحة
            if (document.readyState === 'complete') {
                sendFingerprint();
            } else {
                window.addEventListener('load', sendFingerprint);
            }
        })();
        </script>
        """
