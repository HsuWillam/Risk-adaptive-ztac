/**
 * Browser fingerprint collection — the eight attributes that map 1:1 to the
 * backend FP_ATTRIBUTES list. Values are sent raw; the backend hashes them
 * one-way before storage (privacy-by-design, PDPA/GDPR aligned).
 *
 * Per the IR (FP-Fed finding), fingerprints are most reliably available after a
 * user interaction, so collect() is called on first interaction, not on bare
 * page load. The result is cached for the session.
 */

export interface Fingerprint {
  userAgent: string;
  language: string;
  platform: string;
  screenResolution: string;
  colorDepth: string;
  timezone: string;
  canvasHash: string;
  webglVendor: string;
}

function canvasHash(): string {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "no-canvas";
    ctx.textBaseline = "top";
    ctx.font = "16px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(0, 0, 240, 30);
    ctx.fillStyle = "#069";
    ctx.fillText("ZTAC-fp \u26a1 0123", 4, 8);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("ZTAC-fp \u26a1 0123", 6, 10);
    const data = canvas.toDataURL();
    let h = 0;
    for (let i = 0; i < data.length; i++) {
      h = (h << 5) - h + data.charCodeAt(i);
      h |= 0;
    }
    return String(h >>> 0);
  } catch {
    return "no-canvas";
  }
}

function webglVendor(): string {
  try {
    const canvas = document.createElement("canvas");
    const gl =
      (canvas.getContext("webgl") as WebGLRenderingContext | null) ||
      (canvas.getContext("experimental-webgl") as WebGLRenderingContext | null);
    if (!gl) return "no-webgl";
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    if (!dbg) return gl.getParameter(gl.VENDOR) as string;
    return gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) as string;
  } catch {
    return "no-webgl";
  }
}

let cached: Fingerprint | null = null;

export function collectFingerprint(): Fingerprint {
  if (cached) return cached;
  cached = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: (navigator as any).platform ?? "unknown",
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    colorDepth: String(window.screen.colorDepth),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? "unknown",
    canvasHash: canvasHash(),
    webglVendor: webglVendor(),
  };
  return cached;
}

/** Collect on first user interaction, then resolve. */
export function fingerprintOnInteraction(): Promise<Fingerprint> {
  return new Promise((resolve) => {
    if (cached) return resolve(cached);
    const handler = () => {
      resolve(collectFingerprint());
      window.removeEventListener("pointerdown", handler);
      window.removeEventListener("keydown", handler);
    };
    window.addEventListener("pointerdown", handler, { once: true });
    window.addEventListener("keydown", handler, { once: true });
    // Fallback so login still works if the user submits via Enter immediately.
    setTimeout(() => resolve(collectFingerprint()), 1500);
  });
}
