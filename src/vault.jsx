// Vault.jsx — single-file, 100% in-browser file encryption (AES-256-GCM + PBKDF2) with GSAP animations.
// Needs only:  lucide-react  (react / react-dom already in your project). GSAP is loaded from cdnjs at runtime,
// so there is nothing else to install. If the CDN is unreachable the app still works, just without animations.
// No login, no database, no Tailwind. History is kept only in this browser (localStorage).
import React, { useState, useRef, useEffect, useLayoutEffect, useMemo, useCallback } from "react";
import {
  Lock, Unlock, Eye, EyeOff, Download, ShieldCheck, Upload, FileText, X, Trash2, Copy, Check,
  Sparkles, Send, Moon, Sun, History, Loader2, FileArchive, KeyRound, WifiOff, Cpu, AlertTriangle,
} from "lucide-react";

/* ───────────────────────── GSAP loader (CDN, with a silent no-op fallback) ───────────────────────── */
const GSAP_CDN = "https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/";
const NOOP = new Proxy(function () {}, { get: (_, k) => (k === "then" ? undefined : NOOP), apply: () => NOOP });
let gsap, ScrollTrigger, animated = false, gsapPromise;
const loadScript = (src) => new Promise((resolve, reject) => {
  const old = document.querySelector(`script[src="${src}"]`);
  if (old && old.dataset.ok) return resolve();
  const el = old || document.createElement("script");
  el.src = src;
  el.addEventListener("load", () => { el.dataset.ok = "1"; resolve(); });
  el.addEventListener("error", () => reject(new Error(`Could not load ${src}`)));
  if (!old) document.head.appendChild(el);
});
function loadGsap() {
  gsapPromise = gsapPromise || loadScript(`${GSAP_CDN}gsap.min.js`)
    .then(() => loadScript(`${GSAP_CDN}ScrollTrigger.min.js`))
    .then(() => {
      gsap = window.gsap; ScrollTrigger = window.ScrollTrigger;
      gsap.registerPlugin(ScrollTrigger); animated = true;
    })
    .catch(() => { gsap = NOOP; ScrollTrigger = NOOP; animated = false; });
  return gsapPromise;
}

/* ───────────────────────── Crypto (format unchanged: base64 "VLT1"+salt16+iv12+AES-GCM) ───────────────────────── */
const MAGIC = new TextEncoder().encode("VLT1");
const ITER = 250000;
const LARGE = 100 * 1024 * 1024;
const tick = () => new Promise((r) => setTimeout(r, 0));
const cat = (parts) => {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.byteLength, 0));
  let n = 0;
  parts.forEach((p) => { out.set(p, n); n += p.byteLength; });
  return out;
};
const toB64 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
const fromB64 = (v) => Uint8Array.from(atob(v.replace(/\s/g, "")), (c) => c.charCodeAt(0));
const hasMagic = (b) => MAGIC.every((v, i) => b[i] === v);

async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptFile(file, password, on) {
  on(8, "Reading file…"); await tick();
  const data = new Uint8Array(await file.arrayBuffer());
  const nameB = new TextEncoder().encode(file.name);
  const mimeB = new TextEncoder().encode(file.type || "application/octet-stream");
  if (nameB.length > 0xffff || mimeB.length > 255) throw new Error("File name or type is too long.");
  const head = new Uint8Array(2 + nameB.length + 1 + mimeB.length);
  new DataView(head.buffer).setUint16(0, nameB.length, true);
  head.set(nameB, 2); head[2 + nameB.length] = mimeB.length; head.set(mimeB, 3 + nameB.length);
  on(25, "Deriving key…"); await tick();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  on(65, "Encrypting…"); await tick();
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, cat([head, data])));
  on(95, "Packaging…"); await tick();
  return { blob: new Blob([toB64(cat([MAGIC, salt, iv, cipher]))], { type: "text/plain" }), name: `${file.name}.vault` };
}

async function decryptFile(file, password, on) {
  on(8, "Reading file…"); await tick();
  const raw = new Uint8Array(await file.arrayBuffer());
  let buf = raw;
  if (!hasMagic(raw)) {
    try {
      const txt = new TextDecoder().decode(raw);
      if (/^[A-Za-z0-9+/\s]+=*\s*$/.test(txt)) buf = fromB64(txt);
    } catch { buf = raw; }
  }
  if (buf.length < 48 || !hasMagic(buf)) throw new Error("This doesn't look like a Vault-encrypted file.");
  on(30, "Deriving key…"); await tick();
  const key = await deriveKey(password, buf.slice(4, 20));
  on(70, "Decrypting…"); await tick();
  let p;
  try { p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(20, 32) }, key, buf.slice(32))); }
  catch { throw new Error("Wrong password, or the file is corrupted."); }
  const nl = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint16(0, true);
  const name = new TextDecoder().decode(p.slice(2, 2 + nl));
  const ml = p[2 + nl];
  const mime = new TextDecoder().decode(p.slice(3 + nl, 3 + nl + ml));
  return { blob: new Blob([p.slice(3 + nl + ml)], { type: mime }), name: name || "decrypted-file" };
}

/* ───────────────────────── Helpers ───────────────────────── */
const COMMON = ["password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin", "iloveyou", "111111", "password1"];
function strength(p) {
  if (!p) return { s: 0, l: "", h: "" };
  const cls = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  if (COMMON.includes(p.toLowerCase()) || /^(.)\1+$/.test(p)) return { s: 0, l: "Very weak", h: "Very common password." };
  let s = (p.length >= 8) + (p.length >= 12) + (p.length >= 16) + (cls >= 3);
  if (p.length < 8) s = Math.min(s, 1);
  if (cls === 1) s = Math.min(s, 2);
  return { s, l: ["Very weak", "Weak", "Fair", "Good", "Strong"][s], h: p.length < 12 ? "Aim for 12+ characters." : cls < 3 ? "Mix cases, numbers & symbols." : "" };
}
const rnd = (max) => {
  const lim = Math.floor(0x100000000 / max) * max, b = new Uint32Array(1);
  do crypto.getRandomValues(b); while (b[0] >= lim);
  return b[0] % max;
};
function genPw(len = 20) {
  const sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"];
  const all = sets.join("");
  const c = sets.map((s) => s[rnd(s.length)]);
  while (c.length < len) c.push(all[rnd(all.length)]);
  for (let i = c.length - 1; i > 0; i--) { const j = rnd(i + 1); [c[i], c[j]] = [c[j], c[i]]; }
  return c.join("");
}
const fmtBytes = (n) => {
  if (!n) return "0 B";
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 3);
  const v = n / 1024 ** i;
  return `${v >= 10 || !i ? Math.round(v) : v.toFixed(1)} ${["B", "KB", "MB", "GB"][i]}`;
};
const ago = (t) => {
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return new Date(t).toLocaleDateString();
};
const save = (blob, name) => {
  const u = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(u), 1500);
};
const ls = {
  get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};

// tiny store-only ZIP writer (no dependency)
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
async function makeZip(entries) {
  const enc = new TextEncoder(), seen = {}, parts = [], cen = [];
  let off = 0;
  for (const e of entries) {
    const k = (seen[e.name] = (seen[e.name] || 0) + 1);
    const nm = k > 1 ? e.name.replace(/(\.[^.]*)?$/, ` (${k - 1})$1`) : e.name;
    const nb = enc.encode(nm.replace(/[\\/]/g, "_")), d = new Uint8Array(await e.blob.arrayBuffer()), crc = crc32(d);
    const l = new Uint8Array(30 + nb.length), lv = new DataView(l.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0x800, true); lv.setUint16(12, 0x21, true);
    lv.setUint32(14, crc, true); lv.setUint32(18, d.length, true); lv.setUint32(22, d.length, true); lv.setUint16(26, nb.length, true); l.set(nb, 30);
    const h = new Uint8Array(46 + nb.length), hv = new DataView(h.buffer);
    hv.setUint32(0, 0x02014b50, true); hv.setUint16(4, 20, true); hv.setUint16(6, 20, true); hv.setUint16(8, 0x800, true); hv.setUint16(14, 0x21, true);
    hv.setUint32(16, crc, true); hv.setUint32(20, d.length, true); hv.setUint32(24, d.length, true); hv.setUint16(28, nb.length, true); hv.setUint32(42, off, true); h.set(nb, 46);
    parts.push(l, d); cen.push(h); off += l.length + d.length;
  }
  const end = new Uint8Array(22), ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cen.reduce((s, c) => s + c.length, 0), true); ev.setUint32(16, off, true);
  return new Blob([...parts, ...cen, end], { type: "application/zip" });
}

/* ───────────────────────── GSAP-powered small components ───────────────────────── */
function Magnetic({ children }) {
  const r = useRef(null);
  const move = (e) => {
    const b = r.current.getBoundingClientRect();
    gsap.to(r.current, { x: (e.clientX - b.left - b.width / 2) * 0.25, y: (e.clientY - b.top - b.height / 2) * 0.35, duration: 0.3 });
  };
  const leave = () => gsap.to(r.current, { x: 0, y: 0, duration: 0.8, ease: "elastic.out(1,.4)" });
  return <span ref={r} onMouseMove={move} onMouseLeave={leave} style={{ display: "inline-block" }}>{children}</span>;
}

function CountUp({ to }) {
  const el = useRef(null), v = useRef({ n: 0 });
  useEffect(() => {
    if (!animated) { if (el.current) el.current.textContent = to; return undefined; }
    const tw = gsap.to(v.current, { n: to, duration: 1, ease: "power2.out", onUpdate: () => { if (el.current) el.current.textContent = Math.round(v.current.n); } });
    return () => tw.kill();
  }, [to]);
  return <span ref={el}>0</span>;
}

const PLAIN = "Q3 revenue: $4.2M · CONFIDENTIAL";
const CIPHER = "VkxUMa7Fq9+Zr3Lx0TnB8cE2dYw5Hs/KmP1uJvQeGo4A";
const NOISE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function CipherDemo() {
  const pre = useRef(null), label = useRef(null), pill = useRef(null);
  useEffect(() => {
    const st = { p: 1 };
    const render = (t, p) => { if (pre.current) pre.current.textContent = [...t].map((c, i) => (i < p * t.length ? c : NOISE[rnd(NOISE.length)])).join(""); };
    render(PLAIN, 1);
    const mm = gsap.matchMedia();
    mm.add("(prefers-reduced-motion: no-preference)", () => {
      const tl = gsap.timeline({ repeat: -1 });
      [true, false].forEach((enc) => {
        tl.call(() => {
          if (label.current) label.current.textContent = enc ? "Q3-financials.xlsx.vault" : "Q3-financials.xlsx";
          if (pill.current) { pill.current.textContent = enc ? "Encrypted" : "Plain"; pill.current.className = `pill ${enc ? "g" : "a"}`; }
        })
          .fromTo(st, { p: 0 }, { p: 1, duration: 1.4, ease: "power2.inOut", onUpdate: () => render(enc ? CIPHER : PLAIN, st.p) })
          .to({}, { duration: 2.2 });
      });
    });
    return () => mm.revert();
  }, []);
  return (
    <div className="demo card">
      <div className="bar"><i /><i /><i /><small>vault · in your browser</small></div>
      <div className="dbody">
        <div className="dfile"><FileText size={20} /><strong ref={label}>Q3-financials.xlsx</strong><span ref={pill} className="pill a">Plain</span></div>
        <pre ref={pre} className="dtext" aria-hidden="true" />
        <div className="dkey"><KeyRound size={14} /> ••••••••••••</div>
      </div>
    </div>
  );
}

function FileRow({ it, onRemove, disabled }) {
  const row = useRef(null), bar = useRef(null);
  useLayoutEffect(() => { gsap.from(row.current, { x: -24, opacity: 0, duration: 0.45, ease: "power3.out" }); }, []);
  useEffect(() => { gsap.to(bar.current, { width: `${it.pct}%`, duration: 0.4, ease: "power2.out" }); }, [it.pct]);
  return (
    <div ref={row} className={`frow ${it.status}`}>
      <span className="fico">{it.file.name.endsWith(".vault") ? <Lock size={17} /> : <FileText size={17} />}</span>
      <div className="finfo">
        <div className="fname" title={it.file.name}>{it.file.name}</div>
        <div className="fsub">
          {fmtBytes(it.file.size)}
          {it.file.size > LARGE && <b className="warn"><AlertTriangle size={12} /> Large file</b>}
          {it.status !== "idle" && <span className={it.status === "error" ? "err" : ""}> · {it.msg}</span>}
        </div>
        {(it.status === "work" || it.status === "done") && <div className="prog"><span ref={bar} /></div>}
      </div>
      {it.status === "work" ? <Loader2 size={17} className="spin" /> : it.status === "done" ? <Check size={17} className="okc" /> : (
        <button className="ib" onClick={onRemove} disabled={disabled} aria-label={`Remove ${it.file.name}`}><X size={16} /></button>
      )}
    </div>
  );
}

function DoneModal({ results, isEnc, onClose, onZip, zipping }) {
  const root = useRef(null);
  useLayoutEffect(() => {
    const prev = document.activeElement, ovf = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    root.current.querySelector("button")?.focus();
    const key = (e) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", key);
    const ctx = gsap.context(() => {
      gsap.timeline()
        .from(".mbg", { opacity: 0, duration: 0.25 })
        .from(".mcard", { scale: 0.85, y: 30, opacity: 0, duration: 0.5, ease: "back.out(1.7)" }, "<")
        .fromTo(".mcirc", { strokeDashoffset: 151 }, { strokeDashoffset: 0, duration: 0.6, ease: "power2.out" }, "-=.2")
        .fromTo(".mtick", { strokeDashoffset: 40 }, { strokeDashoffset: 0, duration: 0.4 }, "-=.1")
        .from(".mrow", { x: -20, opacity: 0, stagger: 0.07, duration: 0.35 }, "-=.2");
    }, root);
    return () => { ctx.revert(); document.removeEventListener("keydown", key); document.body.style.overflow = ovf; prev?.focus?.(); };
  }, []); // eslint-disable-line
  return (
    <div ref={root}>
      <div className="mbg" onMouseDown={onClose}>
        <div className="mcard" role="dialog" aria-modal="true" aria-label="Results ready" onMouseDown={(e) => e.stopPropagation()}>
          <button className="ib mx" onClick={onClose} aria-label="Close"><X size={18} /></button>
          <svg className="check" viewBox="0 0 52 52" aria-hidden="true"><circle className="mcirc" cx="26" cy="26" r="24" /><path className="mtick" d="M15 27l8 8 14-16" /></svg>
          <h3>{isEnc ? "Files encrypted" : "Files decrypted"}</h3>
          <p className="mu">{results.length} file{results.length > 1 ? "s" : ""} ready. Nothing was uploaded. Downloads are cleared when you close this.</p>
          <div className="dls">
            {results.map((r) => (
              <a key={r.url} className="btn out block mrow" href={r.url} download={r.name}><Download size={16} /><span>{r.name}</span></a>
            ))}
          </div>
          {results.length > 1 && (
            <button className="btn pri block" onClick={onZip} disabled={zipping}>{zipping ? <Loader2 size={16} className="spin" /> : <FileArchive size={16} />} Download all as ZIP</button>
          )}
        </div>
      </div>
    </div>
  );
}

/* ───────────────────────── Main component ───────────────────────── */
let uid = 0;
function VaultApp() {
  const root = useRef(null), input = useRef(null), dz = useRef(null), toastEl = useRef(null), first = useRef(true), resRef = useRef([]);
  const [dark, setDark] = useState(() => ls.get("vault.dark", window.matchMedia?.("(prefers-color-scheme: dark)").matches));
  const [mode, setMode] = useState("encrypt");
  const [items, setItems] = useState([]);
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState([]);
  const [zipping, setZipping] = useState(false);
  const [hist, setHist] = useState(() => ls.get("vault.history", []));
  const [toast, setToast] = useState(null);

  const enc = mode === "encrypt";
  const st = useMemo(() => strength(pw), [pw]);
  const can = items.length > 0 && pw.length > 0 && !busy;
  const stats = useMemo(() => ({
    e: hist.filter((h) => h.op === "encrypt" && h.ok).length,
    d: hist.filter((h) => h.op === "decrypt" && h.ok).length,
    last: hist[0]?.t,
  }), [hist]);
  resRef.current = results;

  const say = useCallback((m, bad) => setToast({ m, bad, id: Date.now() }), []);
  const patch = (id, p) => setItems((l) => l.map((i) => (i.id === id ? { ...i, ...p } : i)));
  const dropResults = useCallback(() => { resRef.current.forEach((r) => URL.revokeObjectURL(r.url)); setResults([]); }, []);
  useEffect(() => () => resRef.current.forEach((r) => URL.revokeObjectURL(r.url)), []);
  useEffect(() => ls.set("vault.dark", dark), [dark]);

  useEffect(() => {
    if (!toast) return undefined;
    if (!animated) { const t0 = setTimeout(() => setToast(null), 3800); return () => clearTimeout(t0); }
    gsap.fromTo(toastEl.current, { y: 30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, ease: "back.out(1.6)" });
    const t = setTimeout(() => gsap.to(toastEl.current, { y: 20, opacity: 0, duration: 0.3, onComplete: () => setToast(null) }), 3800);
    return () => clearTimeout(t);
  }, [toast]);

  // intro + scroll animations
  useLayoutEffect(() => {
    const ctx = gsap.context(() => {
      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        gsap.timeline({ defaults: { ease: "power3.out" } })
          .from(".nav", { yPercent: -100, opacity: 0, duration: 0.7 })
          .from(".badge", { y: 16, opacity: 0, duration: 0.5 }, "-=.3")
          .from(".h1 .w span", { yPercent: 115, duration: 0.9, stagger: 0.08 }, "-=.3")
          .from(".lead, .cta > *, .trust li", { y: 20, opacity: 0, duration: 0.6, stagger: 0.08 }, "-=.5")
          .from(".demo", { y: 60, opacity: 0, rotateX: -12, transformPerspective: 900, duration: 1 }, "-=1");
        gsap.to(".orb.a", { x: 70, y: 40, duration: 7, yoyo: true, repeat: -1, ease: "sine.inOut" });
        gsap.to(".orb.b", { x: -60, y: -50, duration: 9, yoyo: true, repeat: -1, ease: "sine.inOut" });
        gsap.utils.toArray(".reveal").forEach((el) => gsap.from(el, { y: 40, opacity: 0, duration: 0.8, ease: "power3.out", scrollTrigger: { trigger: el, start: "top 88%" } }));
        gsap.set(".feat", { opacity: 0, y: 40 });
        ScrollTrigger.batch(".feat", { start: "top 92%", once: true, onEnter: (b) => gsap.to(b, { opacity: 1, y: 0, stagger: 0.1, duration: 0.7, ease: "power3.out" }) });
      });
    }, root);
    return () => ctx.revert();
  }, []);

  // mode-switch + drag animations
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    gsap.fromTo(".swap", { y: 12, opacity: 0.3 }, { y: 0, opacity: 1, duration: 0.45, stagger: 0.06, ease: "power3.out" });
  }, [mode]);
  useEffect(() => { gsap.to(dz.current, { scale: drag ? 1.02 : 1, duration: 0.25, ease: "power2.out" }); }, [drag]);

  const addFiles = (list) => {
    const sel = Array.from(list || []);
    if (!sel.length) return;
    dropResults();
    setItems((cur) => {
      const seen = new Set(cur.map((i) => i.key)), next = [...cur];
      sel.forEach((f) => {
        const key = `${f.name}-${f.size}-${f.lastModified}`;
        if (!seen.has(key)) { seen.add(key); next.push({ id: `f${++uid}`, key, file: f, status: "idle", pct: 0, msg: "" }); }
      });
      return next;
    });
    if (sel.some((f) => f.size > LARGE)) say("Files over 100 MB are processed in memory and may be slow.");
  };

  const switchMode = (m) => { if (busy || m === mode) return; setMode(m); setItems([]); dropResults(); };

  const run = async () => {
    if (!can) return;
    setBusy(true); dropResults();
    const out = [], log = [];
    for (const it of items) {
      patch(it.id, { status: "work", pct: 3, msg: "Starting…" });
      try {
        const r = await (enc ? encryptFile : decryptFile)(it.file, pw, (pct, msg) => patch(it.id, { pct, msg }));
        out.push({ ...r, url: URL.createObjectURL(r.blob) });
        patch(it.id, { status: "done", pct: 100, msg: "Done" });
        log.push({ id: `${Date.now()}-${log.length}`, op: mode, name: it.file.name, size: it.file.size, ok: true, t: Date.now() });
      } catch (e) {
        patch(it.id, { status: "error", pct: 0, msg: e.message || "Something went wrong." });
        log.push({ id: `${Date.now()}-${log.length}`, op: mode, name: it.file.name, size: it.file.size, ok: false, t: Date.now() });
      }
    }
    if (out.length) { setResults(out); setPw(""); say(`${out.length} file${out.length > 1 ? "s" : ""} ${enc ? "encrypted" : "decrypted"}.`); }
    if (out.length < items.length) say(`${items.length - out.length} file(s) failed. See the list.`, true);
    setItems((l) => l.filter((i) => i.status === "error"));
    setHist((h) => { const n = [...log.reverse(), ...h].slice(0, 200); ls.set("vault.history", n); return n; });
    setBusy(false);
  };

  const zip = async () => {
    setZipping(true);
    try { save(await makeZip(results), `vault-${Date.now()}.zip`); } catch { say("Could not create ZIP.", true); }
    setZipping(false);
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(pw); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch { say("Clipboard blocked.", true); }
  };

  const delHist = (id) => setHist((h) => { const n = h.filter((x) => x.id !== id); ls.set("vault.history", n); return n; });
  const clearHist = () => { setHist([]); ls.set("vault.history", []); say("History cleared."); };
  const go = (id) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });

  return (
    <div ref={root} className={`vt ${dark ? "dark" : ""}`}>
      <style>{CSS}</style>
      <div className="orb a" /><div className="orb b" />

      <header className="nav">
        <div className="wrap navin">
          <span className="logo"><span className="lm"><Lock size={16} strokeWidth={2.4} /></span>Vault</span>
          <nav className="links"><button onClick={() => go("vault")}>Workspace</button><button onClick={() => go("history")}>History</button><button onClick={() => go("security")}>Security</button></nav>
          <button className="ib bx" onClick={() => setDark((d) => !d)} aria-label="Toggle theme">{dark ? <Sun size={18} /> : <Moon size={18} />}</button>
        </div>
      </header>

      <main>
        <section className="wrap hero">
          <div className="hcopy">
            <span className="badge"><ShieldCheck size={14} /> Zero-knowledge · 100% in your browser</span>
            <h1 className="h1">
              {["Encrypt", "anything."].map((w) => <span className="w" key={w}><span>{w}</span></span>)}<br />
              {["Trust", "no", "server."].map((w) => <span className="w grad" key={w}><span>{w}</span></span>)}
            </h1>
            <p className="lead">Lock files with AES-256-GCM directly on your device. No account, no uploads, no database. Your files and passwords never leave this tab.</p>
            <div className="cta">
              <Magnetic><button className="btn pri lg" onClick={() => go("vault")}>Start encrypting <Send size={17} /></button></Magnetic>
              <Magnetic><button className="btn out lg" onClick={() => go("security")}>How it's secured</button></Magnetic>
            </div>
            <ul className="trust"><li><Lock size={14} /> AES-256-GCM</li><li><WifiOff size={14} /> Works offline</li><li><Cpu size={14} /> PBKDF2 · 250k rounds</li></ul>
          </div>
          <CipherDemo />
        </section>

        <section id="vault" className="wrap sec" data-mode={mode}>
          <div className="stats reveal">
            <div className="card stat"><span className="si g"><Lock size={18} /></span><div><small>Files encrypted</small><b><CountUp to={stats.e} /></b></div></div>
            <div className="card stat"><span className="si a"><Unlock size={18} /></span><div><small>Files decrypted</small><b><CountUp to={stats.d} /></b></div></div>
            <div className="card stat"><span className="si"><History size={18} /></span><div><small>Last activity</small><b className="sm">{stats.last ? ago(stats.last) : "No activity yet"}</b></div></div>
          </div>

          <div className="card work reveal">
            <div className="seg" role="group" aria-label="Mode">
              {["encrypt", "decrypt"].map((m) => (
                <button key={m} className={mode === m ? "on" : ""} aria-pressed={mode === m} onClick={() => switchMode(m)} disabled={busy}>
                  {m === "encrypt" ? <Lock size={15} /> : <Unlock size={15} />}{m === "encrypt" ? "Encrypt" : "Decrypt"}
                </button>
              ))}
            </div>

            <div ref={dz} className={`dz swap ${drag ? "drag" : ""}`} role="button" tabIndex={0} aria-label="Choose files or drop them here"
              onClick={() => input.current?.click()}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); addFiles(e.dataTransfer.files); }}>
              <input ref={input} type="file" multiple hidden onChange={(e) => { addFiles(e.target.files); e.target.value = ""; }} />
              <span className="dico"><Upload size={22} /></span>
              <strong>{drag ? "Drop to add files" : "Drop files here, or click to browse"}</strong>
              <span className="mu sm">{enc ? "Any file type · stays on this device" : "Select .vault files created by this app"}</span>
            </div>

            {items.length > 0 && (
              <div className="flist">
                <div className="fhead"><span>{items.length} file{items.length > 1 ? "s" : ""} selected</span><button className="lnk" onClick={() => setItems([])} disabled={busy}>Clear all</button></div>
                {items.map((it) => <FileRow key={it.id} it={it} disabled={busy} onRemove={() => setItems((l) => l.filter((x) => x.id !== it.id))} />)}
              </div>
            )}

            <div className="field swap">
              <label htmlFor="pw">Password</label>
              <div className="irow">
                <input id="pw" className="inp" type={show ? "text" : "password"} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="off"
                  placeholder={enc ? "Choose a strong password" : "Password used to encrypt"} />
                <button className="ib bx" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
                {enc && <button className="ib bx" onClick={() => { setPw(genPw(20)); setShow(true); }} aria-label="Generate strong password" title="Generate"><Sparkles size={17} /></button>}
                {enc && <button className="ib bx" onClick={copy} disabled={!pw} aria-label="Copy password">{copied ? <Check size={17} /> : <Copy size={17} />}</button>}
              </div>
              {enc && pw && (
                <div className="meter">
                  <div className={`bars s${st.s}`}>{[0, 1, 2, 3, 4].map((i) => <span key={i} className={i <= st.s ? "on" : ""} />)}</div>
                  <small className="mu">{st.l}{st.h ? ` · ${st.h}` : ""}</small>
                </div>
              )}
            </div>

            <p className="note swap"><ShieldCheck size={15} /><span><b>Zero-knowledge:</b> your password and files never leave this device, so a lost password can't be recovered. Store it safely.</span></p>

            <button className="btn pri lg block swap" onClick={run} disabled={!can}>
              {busy ? <><Loader2 size={18} className="spin" /> Working…</> : <>{enc ? <Lock size={18} /> : <Unlock size={18} />} {enc ? "Encrypt" : "Decrypt"} {items.length > 1 ? `${items.length} files` : "file"}</>}
            </button>
          </div>
        </section>

        <section id="history" className="wrap sec">
          <div className="hrow reveal">
            <div><h2>History</h2><p className="mu sm">Stored only in this browser: file name, size and time. Never contents or passwords.</p></div>
            <button className="btn dng sm" onClick={clearHist} disabled={!hist.length}><Trash2 size={15} /> Clear</button>
          </div>
          <div className="card hist reveal">
            {hist.length === 0 ? <div className="empty"><History size={30} /><p className="mu">No activity yet. Encrypt or decrypt a file and it appears here.</p></div> : (
              <ul>{hist.slice(0, 30).map((h) => (
                <li key={h.id}>
                  <span className={`si ${h.op === "encrypt" ? "g" : "a"}`}>{h.op === "encrypt" ? <Lock size={15} /> : <Unlock size={15} />}</span>
                  <div className="hn"><b title={h.name}>{h.name}</b><small className="mu">{fmtBytes(h.size)} · {ago(h.t)}</small></div>
                  <span className={`pill ${h.ok ? "g" : "r"}`}>{h.ok ? (h.op === "encrypt" ? "Encrypted" : "Decrypted") : "Failed"}</span>
                  <button className="ib" onClick={() => delHist(h.id)} aria-label={`Delete ${h.name} from history`}><Trash2 size={15} /></button>
                </li>
              ))}</ul>
            )}
          </div>
        </section>

        <section id="security" className="wrap sec">
          <h2 className="ctr reveal">Security you can verify</h2>
          <p className="mu ctr reveal" style={{ marginBottom: 28 }}>Standard, well-reviewed primitives. Nothing exotic.</p>
          <div className="feats">
            {[[ShieldCheck, "AES-256-GCM", "Authenticated encryption detects tampering and wrong passwords."],
              [Cpu, "PBKDF2 · 250,000 rounds", "SHA-256 key derivation with a fresh random salt for every file."],
              [WifiOff, "Local-only", "Runs on the Web Crypto API. Files and passwords never touch a server."],
              [KeyRound, "Password generator", "Unbiased secure randomness and a live strength meter."],
              [FileArchive, "Batch & ZIP", "Process many files at once and grab everything as one ZIP."],
              [History, "Private history", "Kept in your own browser storage. Clear it any time."]].map(([I, t, d]) => (
              <div key={t} className="card feat"><span className="si g"><I size={20} /></span><h3>{t}</h3><p className="mu">{d}</p></div>
            ))}
          </div>
        </section>
      </main>

      <footer className="wrap foot"><span className="logo"><span className="lm"><Lock size={16} /></span>Vault</span><small className="mu">© {new Date().getFullYear()} Vault · Your data stays yours.</small></footer>

      {results.length > 0 && <DoneModal results={results} isEnc={enc} zipping={zipping} onZip={zip} onClose={dropResults} />}
      <div className="toasts" role="status" aria-live="polite">{toast && <div ref={toastEl} key={toast.id} className={`toast ${toast.bad ? "bad" : ""}`}>{toast.m}</div>}</div>
    </div>
  );
}

/* ───────────────────────── Styles (scoped to .vt) ───────────────────────── */
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
.vt{--bg:#f5f7f8;--card:rgba(255,255,255,.76);--solid:#fff;--s2:#f1f3f5;--bd:#e2e6ea;--tx:#1b222c;--mu:#5f6b79;--g:#2f9e76;--gs:#1f7a59;--gl:#eaf6f0;--a:#c68a2e;--as:#956414;--al:#fbf3e4;--r:#c13f3f;--rl:#fbecec;--on:#fff;--g1:rgba(255,255,255,.82);--g2:rgba(255,255,255,.5);--gb:rgba(255,255,255,.75);--btnbg:#fff;--m1:#3b82f6;--m2:#7ef0d4;--m3:#f6c9a8;
 --ac:var(--g);--acs:var(--gs);--acl:var(--gl);--sh:0 1px 2px rgba(27,34,44,.04),0 18px 40px -24px rgba(27,34,44,.22);
 font-family:Inter,system-ui,sans-serif;font-size:15px;line-height:1.55;color:var(--tx);background:var(--bg);min-height:100vh;position:relative;overflow-x:hidden;transition:background .3s,color .3s}
.vt.dark{--bg:#0c1117;--card:rgba(22,29,38,.74);--solid:#141b24;--s2:#1a232e;--bd:#263140;--tx:#e8edf3;--mu:#94a1b1;--g:#3bb98c;--gs:#3bb98c;--gl:rgba(59,185,140,.14);--a:#e0a646;--as:#e0a646;--al:rgba(224,166,70,.14);--r:#ef7b7b;--rl:rgba(239,123,123,.14);--on:#06150f;--g1:rgba(255,255,255,.085);--g2:rgba(255,255,255,.02);--gb:rgba(255,255,255,.13);--btnbg:#101218;--sh:0 1px 2px rgba(0,0,0,.3),0 18px 40px -22px rgba(0,0,0,.6)}
.vt [data-mode=decrypt]{--ac:var(--a);--acs:var(--as);--acl:var(--al);--m1:#f59e0b;--m2:#fb7185;--m3:#c084fc}
.vt *{box-sizing:border-box}.vt h1,.vt h2,.vt h3,.vt p{margin:0}.vt button{font:inherit;color:inherit;cursor:pointer}.vt :focus-visible{outline:2px solid var(--acs);outline-offset:2px;border-radius:8px}
.vt .mu{color:var(--mu)}.vt .sm{font-size:13px}.vt .ctr{text-align:center}.vt .spin{animation:vspin .9s linear infinite}@keyframes vspin{to{transform:rotate(360deg)}}
.vt .orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.34;pointer-events:none;z-index:0}.vt .orb.a{width:480px;height:480px;background:#4f8cff;top:-120px;left:-120px}.vt .orb.b{width:420px;height:420px;background:#f0a6ff;bottom:-120px;right:-100px}
.vt main,.vt .nav,.vt .foot{position:relative;z-index:1}.vt .wrap{max-width:1120px;margin:0 auto;padding:0 20px}
.vt .card{background:linear-gradient(145deg,var(--g1),var(--g2));-webkit-backdrop-filter:blur(22px) saturate(165%);backdrop-filter:blur(22px) saturate(165%);border:1px solid var(--gb);border-radius:20px;box-shadow:var(--sh),inset 0 1px 0 rgba(255,255,255,.4)}
.vt .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 18px;border-radius:12px;border:1px solid transparent;font-weight:600;white-space:nowrap;text-decoration:none;transition:transform .15s,border-color .15s,opacity .15s}
.vt .btn:hover:not(:disabled){transform:translateY(-1px)}.vt .btn:disabled{opacity:.5;cursor:not-allowed}.vt .lg{padding:13px 22px;border-radius:14px;font-size:15.5px}.vt .block{width:100%}
.vt .pri{background:var(--acs);color:var(--on);box-shadow:0 10px 22px -12px var(--acs)}.vt .out{background:var(--solid);border-color:var(--bd);color:var(--tx)}.vt .out:hover:not(:disabled){border-color:var(--ac)}.vt .dng{background:var(--rl);color:var(--r)}
.vt .ib{display:inline-grid;place-items:center;width:38px;height:38px;border:0;border-radius:10px;background:none;color:var(--mu);flex:none;transition:background .15s}.vt .ib:hover:not(:disabled){background:var(--s2);color:var(--tx)}.vt .ib:disabled{opacity:.4}.vt .bx{border:1px solid var(--bd);background:var(--solid)}
.vt .lnk{background:none;border:0;color:var(--acs);font-weight:600;font-size:13px}
.vt .nav{position:sticky;top:0;z-index:40;background:var(--card);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}.vt .navin{display:flex;align-items:center;justify-content:space-between;height:64px;gap:16px}
.vt .links{display:flex;gap:24px;margin-left:auto}.vt .links button{background:none;border:0;color:var(--mu);font-weight:500}.vt .links button:hover{color:var(--tx)}
.vt .logo{display:inline-flex;align-items:center;gap:10px;font-weight:800;font-size:19px;letter-spacing:-.02em}.vt .lm{width:32px;height:32px;border-radius:10px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,#3bb98c,#1f7a59)}
.vt .hero{display:grid;grid-template-columns:1.1fr 1fr;gap:48px;align-items:center;padding-top:72px;padding-bottom:56px}.vt .hcopy{display:flex;flex-direction:column;gap:22px}
.vt .badge{align-self:flex-start;display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:99px;background:var(--gl);color:var(--gs);font-weight:600;font-size:13px}.vt.dark .badge{color:var(--g)}
.vt .h1{font-size:clamp(38px,5.4vw,62px);font-weight:800;letter-spacing:-.04em;line-height:1.06}.vt .w{display:inline-block;overflow:hidden;vertical-align:top;padding-bottom:.08em;margin-right:.22em}.vt .w span{display:inline-block}
.vt .grad span{background:linear-gradient(120deg,#2f9e76,#c68a2e);-webkit-background-clip:text;background-clip:text;color:transparent;padding-right:.04em}.vt .lead{font-size:18px;color:var(--mu);max-width:520px}
.vt .cta{display:flex;gap:12px;flex-wrap:wrap}.vt .trust{list-style:none;margin:0;padding:0;display:flex;gap:18px;flex-wrap:wrap;color:var(--mu);font-size:13.5px}.vt .trust li{display:flex;gap:6px;align-items:center}
.vt .demo{overflow:hidden}.vt .bar{display:flex;align-items:center;gap:6px;padding:12px 14px;border-bottom:1px solid var(--bd)}.vt .bar i{width:10px;height:10px;border-radius:50%;background:var(--bd)}.vt .bar small{margin-left:8px;color:var(--mu);font-size:12px}
.vt .dbody{padding:22px;display:flex;flex-direction:column;gap:16px}.vt .dfile{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--bd);border-radius:14px;background:var(--solid)}.vt .dfile strong{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vt .dtext{margin:0;min-height:96px;padding:16px;border-radius:14px;background:var(--s2);font:13px/1.7 'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all}.vt .dkey{font:13px 'JetBrains Mono',monospace;color:var(--mu);display:flex;gap:8px;align-items:center}
.vt .pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600}.vt .pill.g{background:var(--gl);color:var(--gs)}.vt .pill.a{background:var(--al);color:var(--as)}.vt .pill.r{background:var(--rl);color:var(--r)}.vt.dark .pill.g{color:var(--g)}
.vt .sec{padding-top:44px;padding-bottom:44px}.vt h2{font-size:clamp(24px,3.2vw,34px);letter-spacing:-.03em}.vt h3{font-size:16px;font-weight:700}
.vt .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px}.vt .stat{display:flex;gap:14px;align-items:center;padding:16px 18px}.vt .stat small{display:block;font-size:12.5px;font-weight:600;color:var(--mu)}.vt .stat b{font-size:26px;font-weight:800;letter-spacing:-.03em;line-height:1.2}.vt .stat b.sm{font-size:16px;font-weight:700;line-height:1.8}
.vt .si{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:var(--s2);color:var(--mu);flex:none}.vt .si.g{background:var(--gl);color:var(--g)}.vt .si.a{background:var(--al);color:var(--a)}
.vt .work{max-width:760px;margin:0 auto;padding:24px;display:flex;flex-direction:column;gap:18px}
.vt .seg{display:flex;gap:4px;padding:4px;background:var(--s2);border:1px solid var(--bd);border-radius:13px}.vt .seg button{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:9px;border:0;border-radius:10px;background:none;color:var(--mu);font-weight:600;transition:background .25s,color .25s}.vt .seg button.on{background:var(--acs);color:var(--on)}
.vt .dz{display:flex;flex-direction:column;align-items:center;gap:6px;padding:32px 16px;text-align:center;border:2px dashed var(--bd);border-radius:16px;cursor:pointer;transition:border-color .2s,background .2s}.vt .dz:hover,.vt .dz.drag{border-color:var(--ac);background:var(--acl)}
.vt .dico{width:48px;height:48px;border-radius:15px;display:grid;place-items:center;background:var(--acl);color:var(--acs)}
.vt .flist{display:flex;flex-direction:column;gap:8px}.vt .fhead{display:flex;justify-content:space-between;font-size:13px;font-weight:600;color:var(--mu)}
.vt .frow{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--bd);border-radius:13px;background:var(--solid)}.vt .frow.error{border-color:var(--r)}.vt .fico{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:var(--acl);color:var(--acs);flex:none}
.vt .finfo{flex:1;min-width:0}.vt .fname{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vt .fsub{font-size:12.5px;color:var(--mu)}.vt .warn{color:var(--as);margin-left:8px;display:inline-flex;align-items:center;gap:3px}.vt .err{color:var(--r)}.vt .okc{color:var(--g)}
.vt .prog{height:5px;margin-top:6px;border-radius:5px;background:var(--s2);overflow:hidden}.vt .prog span{display:block;height:100%;width:0;border-radius:5px;background:linear-gradient(90deg,var(--ac),var(--acs))}
.vt .field{display:flex;flex-direction:column;gap:6px}.vt .field label{font-size:13px;font-weight:600;color:var(--mu)}.vt .irow{display:flex;gap:8px}
.vt .inp{flex:1;min-width:0;padding:11px 13px;border-radius:11px;border:1px solid var(--bd);background:var(--solid);color:var(--tx);font:14px 'JetBrains Mono',monospace;outline:none;transition:border-color .15s,box-shadow .15s}.vt .inp:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--acl)}
.vt .meter{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.vt .bars{display:flex;gap:4px}.vt .bars span{width:26px;height:5px;border-radius:4px;background:var(--bd);transition:background .25s}
.vt .bars.s0 .on,.vt .bars.s1 .on{background:var(--r)}.vt .bars.s2 .on{background:var(--a)}.vt .bars.s3 .on,.vt .bars.s4 .on{background:var(--g)}
.vt .note{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:var(--mu);background:var(--acl);border-radius:12px;padding:11px 13px}.vt .note svg{flex:none;margin-top:2px;color:var(--acs)}
.vt .hrow{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:16px;max-width:760px;margin-left:auto;margin-right:auto}.vt .hist{max-width:760px;margin:0 auto;overflow:hidden}.vt .hist ul{list-style:none;margin:0;padding:6px}
.vt .hist li{display:flex;align-items:center;gap:12px;padding:10px;border-radius:12px;transition:background .15s}.vt .hist li:hover{background:var(--s2)}.vt .hn{flex:1;min-width:0;display:flex;flex-direction:column}.vt .hn b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vt .empty{display:flex;flex-direction:column;align-items:center;gap:8px;padding:40px 16px;color:var(--mu);text-align:center}
.vt .feats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.vt .feat{padding:24px;display:flex;flex-direction:column;gap:10px;transition:border-color .25s,box-shadow .25s}.vt .feat:hover{border-color:var(--g);box-shadow:0 24px 44px -22px var(--g)}
.vt .foot{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding-top:28px;padding-bottom:36px;border-top:1px solid var(--bd)}
.vt .mbg{position:fixed;inset:0;z-index:90;display:grid;place-items:center;padding:16px;background:rgba(10,15,22,.5);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}
.vt .mcard{position:relative;width:100%;max-width:400px;max-height:92vh;overflow:auto;background:var(--solid);border:1px solid var(--bd);border-radius:20px;padding:28px 24px 24px;display:flex;flex-direction:column;gap:10px;text-align:center;box-shadow:0 30px 70px -20px rgba(0,0,0,.45)}.vt .mx{position:absolute;top:10px;right:10px}
.vt .check{width:64px;height:64px;margin:0 auto;fill:none;stroke:var(--acs);stroke-width:3;stroke-linecap:round;stroke-linejoin:round}.vt .mcirc{stroke-dasharray:151}.vt .mtick{stroke-dasharray:40}.vt .dls{display:grid;gap:8px;max-height:220px;overflow:auto;margin:6px 0}.vt .dls span{overflow:hidden;text-overflow:ellipsis}.vt .mrow,.vt .mcard,.vt .mbg,.vt .swap{transition-property:border-color,background,box-shadow!important}
.vt .toasts{position:fixed;right:16px;bottom:16px;z-index:100}.vt .toast{padding:12px 16px;background:var(--solid);border:1px solid var(--bd);border-left:4px solid var(--g);border-radius:12px;box-shadow:var(--sh);font-size:14px;max-width:320px}.vt .toast.bad{border-left-color:var(--r)}
.vt .pri,.vt .seg button.on{color:#0b1220;border:1px solid rgba(255,255,255,.6);
 background:radial-gradient(60% 85% at 50% 128%,rgba(255,255,255,.98),transparent 72%),radial-gradient(60% 130% at 8% 35%,var(--m1),transparent 72%),radial-gradient(55% 130% at 96% 65%,var(--m3),transparent 72%),linear-gradient(90deg,var(--m2),#e8ecff);
 background-size:100% 100%,150% 150%,150% 150%,100% 100%;background-position:0 0,0 0,100% 100%,0 0;
 -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);
 box-shadow:inset 0 1px 0 rgba(255,255,255,.8),inset 0 -10px 18px -10px rgba(255,255,255,.7),0 16px 32px -16px var(--m1);
 transition:background-position .6s ease,box-shadow .3s,filter .3s}
.vt .pri{border-radius:999px;font-weight:700}.vt .pri:hover:not(:disabled){background-position:0 0,100% 0,0 100%,0 0;filter:saturate(1.2) brightness(1.03);box-shadow:inset 0 1px 0 rgba(255,255,255,.9),inset 0 -10px 18px -10px #fff,0 20px 40px -14px var(--m1)}
.vt .seg{border-radius:999px;padding:5px}.vt .seg button{border-radius:999px}.vt .seg button.on{box-shadow:inset 0 1px 0 rgba(255,255,255,.8),0 8px 20px -10px var(--m1)}
.vt .out{border-radius:999px;color:var(--tx);border:1.5px solid transparent;
 background:linear-gradient(var(--btnbg),var(--btnbg)) padding-box,linear-gradient(100deg,#5eead4,#a3e635 32%,#f472b6 68%,#60a5fa) border-box;background-size:100% 100%,220% 100%;background-position:0 0,0 0;
 box-shadow:0 12px 26px -16px rgba(0,0,0,.45);transition:background-position .7s ease,box-shadow .3s}
.vt .out:hover:not(:disabled){background-position:0 0,100% 0;border-color:transparent;box-shadow:0 16px 34px -14px #a78bfa}
.vt .dng{border-radius:999px}.vt .dz{border-radius:22px}.vt .inp{border-radius:14px}
@media(max-width:960px){.vt .hero{grid-template-columns:1fr;padding-top:44px}.vt .feats{grid-template-columns:1fr 1fr}.vt .links{display:none}.vt .navin{justify-content:space-between}}
@media(max-width:640px){.vt .stats,.vt .feats{grid-template-columns:1fr}.vt .work{padding:16px}.vt .hrow{flex-direction:column;align-items:flex-start}}
@media(prefers-reduced-motion:reduce){.vt *{transition:none!important;animation:none!important}}
`;

/* ───────────────────────── Entry: waits for GSAP, then renders the app ───────────────────────── */
export default function Vault() {
  const [ready, setReady] = useState(Boolean(gsap));
  useEffect(() => {
    if (gsap) return undefined;
    let live = true;
    loadGsap().then(() => live && setReady(true));
    return () => { live = false; };
  }, []);
  return ready ? <VaultApp /> : <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", fontFamily: "system-ui,sans-serif", color: "#5f6b79" }}>Loading…</div>;
}



//OFFICIAL WEBSITE



// import React, { useState, useRef, useCallback } from "react";
// import { Lock, Eye, EyeOff, Download, ShieldCheck, ShieldAlert } from "lucide-react";

// const MAGIC = new TextEncoder().encode("VLT1");
// const PBKDF2_ITERATIONS = 250000;

// const styles = {
//   page: {
//     minHeight: "100vh",
//     width: "100%",
//     display: "flex",
//     alignItems: "center",
//     justifyContent: "center",
//     padding: "32px 16px",
//     background:
//       "radial-gradient(circle at 12% 0%, rgba(47,158,118,0.06), transparent 45%), radial-gradient(circle at 88% 100%, rgba(198,138,46,0.06), transparent 45%), #F5F7F8",
//     fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Roboto, sans-serif",
//     color: "#1B222C",
//   },
//   card: {
//     width: "100%",
//     maxWidth: 440,
//     background: "#FFFFFF",
//     border: "1px solid #E2E6EA",
//     borderRadius: 16,
//     padding: 32,
//     boxShadow: "0 24px 48px -28px rgba(27,34,44,0.18)",
//   },
//   smallText: { color: "#6B7684", fontSize: 13 },
//   darkText: { color: "#1B222C" },
//   input: {
//     flex: 1,
//     background: "#F8F9FA",
//     border: "1px solid #E2E6EA",
//     color: "#1B222C",
//     borderRadius: 9,
//     padding: "10px 12px",
//     fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
//     fontSize: 14,
//     outline: "none",
//   },
//   actionButton: {
//     width: "100%",
//     padding: "12px 0",
//     border: "none",
//     borderRadius: 10,
//     fontSize: 14.5,
//     fontWeight: 700,
//   },
// };

// function concatBuffers(parts) {
//   const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
//   const output = new Uint8Array(total);
//   let offset = 0;
//   parts.forEach((part) => {
//     output.set(new Uint8Array(part), offset);
//     offset += part.byteLength;
//   });
//   return output;
// }

// function bytesToBase64(bytes) {
//   let binary = "";
//   const chunkSize = 0x8000;
//   for (let index = 0; index < bytes.length; index += chunkSize) {
//     binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
//   }
//   return btoa(binary);
// }

// function base64ToBytes(value) {
//   const binary = atob(value.replace(/\s/g, ""));
//   const bytes = new Uint8Array(binary.length);
//   for (let index = 0; index < binary.length; index += 1) {
//     bytes[index] = binary.charCodeAt(index);
//   }
//   return bytes;
// }

// function createHeader(name, mimeType) {
//   const nameBytes = new TextEncoder().encode(name);
//   const mimeBytes = new TextEncoder().encode(mimeType || "application/octet-stream");
//   const header = new Uint8Array(2 + nameBytes.length + 1 + mimeBytes.length);
//   const view = new DataView(header.buffer);
//   view.setUint16(0, nameBytes.length, true);
//   header.set(nameBytes, 2);
//   header[2 + nameBytes.length] = mimeBytes.length;
//   header.set(mimeBytes, 3 + nameBytes.length);
//   return header;
// }

// async function deriveKey(password, salt) {
//   const baseKey = await crypto.subtle.importKey(
//     "raw",
//     new TextEncoder().encode(password),
//     "PBKDF2",
//     false,
//     ["deriveKey"]
//   );

//   return crypto.subtle.deriveKey(
//     { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
//     baseKey,
//     { name: "AES-GCM", length: 256 },
//     false,
//     ["encrypt", "decrypt"]
//   );
// }

// async function encryptFile(file, password, updateStatus) {
//   updateStatus("Reading file…");
//   const fileBuffer = await file.arrayBuffer();
//   const payload = concatBuffers([createHeader(file.name, file.type), new Uint8Array(fileBuffer)]);

//   updateStatus("Deriving encryption key…");
//   const salt = crypto.getRandomValues(new Uint8Array(16));
//   const iv = crypto.getRandomValues(new Uint8Array(12));
//   const key = await deriveKey(password, salt);

//   updateStatus("Encrypting…");
//   const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
//   const encryptedBytes = concatBuffers([MAGIC, salt, iv, new Uint8Array(cipher)]);
//   return new Blob([bytesToBase64(encryptedBytes)], {
//     type: "text/plain",
//   });
// }

// async function decryptFile(file, password, updateStatus) {
//   updateStatus("Reading file…");
//   const rawBuffer = new Uint8Array(await file.arrayBuffer());
//   let buffer = rawBuffer;

//   try {
//     const text = new TextDecoder().decode(rawBuffer);
//     if (/^[A-Za-z0-9+/\s]+=*$/.test(text)) {
//       buffer = base64ToBytes(text);
//     }
//   } catch {
//     buffer = rawBuffer;
//   }

//   if (new TextDecoder().decode(buffer.slice(0, 4)) !== "VLT1") {
//     throw new Error("This doesn't look like a Vault-encrypted file.");
//   }

//   const salt = buffer.slice(4, 20);
//   const iv = buffer.slice(20, 32);
//   const ciphertext = buffer.slice(32);

//   updateStatus("Deriving decryption key…");
//   const key = await deriveKey(password, salt);

//   updateStatus("Decrypting…");
//   let payload;
//   try {
//     payload = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
//   } catch {
//     throw new Error("Wrong password, or the file is corrupted.");
//   }

//   const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
//   const nameLength = view.getUint16(0, true);
//   const fileName = new TextDecoder().decode(payload.slice(2, 2 + nameLength));
//   const mimeLength = payload[2 + nameLength];
//   const mimeStart = 3 + nameLength;
//   const mimeType = new TextDecoder().decode(payload.slice(mimeStart, mimeStart + mimeLength));
//   const fileBytes = payload.slice(mimeStart + mimeLength);

//   return { blob: new Blob([fileBytes], { type: mimeType }), name: fileName };
// }

// export default function Vault() {
//   const [mode, setMode] = useState("encrypt");
//   const [files, setFiles] = useState([]);
//   const [password, setPassword] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [dragging, setDragging] = useState(false);
//   const [status, setStatus] = useState({ text: "", type: "" });
//   const [downloadLinks, setDownloadLinks] = useState([]);
//   const [busy, setBusy] = useState(false);
//   const [showSuccessModal, setShowSuccessModal] = useState(false);

//   const fileInputRef = useRef(null);
//   const isEncrypt = mode === "encrypt";
//   const canSubmit = files.length > 0 && password && !busy;

//   const resetAll = () => {
//     setFiles([]);
//     setStatus({ text: "", type: "" });
//     setDownloadLinks([]);
//     setShowSuccessModal(false);
//     if (fileInputRef.current) fileInputRef.current.value = "";
//   };

//   const switchMode = (nextMode) => {
//     setMode(nextMode);
//     resetAll();
//   };

//   const handleFiles = useCallback((incomingFiles) => {
//     if (!incomingFiles?.length) return;
//     const selected = Array.from(incomingFiles).filter(Boolean);
//     if (!selected.length) return;

//     setFiles((current) => {
//       const seen = new Set(current.map((item) => `${item.name}-${item.size}-${item.lastModified}`));
//       const result = [...current];
//       selected.forEach((file) => {
//         const key = `${file.name}-${file.size}-${file.lastModified}`;
//         if (!seen.has(key)) {
//           result.push(file);
//           seen.add(key);
//         }
//       });
//       return result;
//     });

//     setStatus({ text: "", type: "" });
//     setDownloadLinks([]);
//     setShowSuccessModal(false);
//   }, []);

//   const onDrop = (event) => {
//     event.preventDefault();
//     setDragging(false);
//     if (event.dataTransfer.files?.length) handleFiles(event.dataTransfer.files);
//   };

//   const runAction = async () => {
//     if (!canSubmit) return;
//     setBusy(true);
//     setStatus({ text: "", type: "" });
//     setDownloadLinks([]);
//     setShowSuccessModal(false);

//     try {
//       const result = [];
//       for (const file of files) {
//         if (isEncrypt) {
//           const blob = await encryptFile(file, password, (text) => setStatus({ text, type: "" }));
//           result.push({ url: URL.createObjectURL(blob), name: file.name + ".vault" });
//         } else {
//           const { blob, name } = await decryptFile(file, password, (text) => setStatus({ text, type: "" }));
//           result.push({ url: URL.createObjectURL(blob), name });
//         }
//       }

//       setDownloadLinks(result);
//       setPassword("");
//       setFiles([]);
//       setShowSuccessModal(true);
//       if (fileInputRef.current) fileInputRef.current.value = "";
//     } catch (error) {
//       setStatus({ text: error.message || "Something went wrong.", type: "error" });
//     } finally {
//       setBusy(false);
//     }
//   };

//   return (
//     <div style={styles.page}>
//       <div style={styles.card}>
//         <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
//           <div style={{ width: 30, height: 30, borderRadius: 8, background: "#EAF6F0", display: "flex", alignItems: "center", justifyContent: "center" }}>
//             <Lock size={16} color="#2F9E76" strokeWidth={2.2} />
//           </div>
//           <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0 }}>Vault</h1>
//         </div>

//         <div style={{ ...styles.smallText, margin: "4px 0 24px 40px" }}>
//           Local, in-browser AES-256 file encryption
//         </div>

//         <div style={{ display: "flex", background: "#F1F3F5", border: "1px solid #E2E6EA", borderRadius: 10, padding: 4, marginBottom: 20 }}>
//           {["encrypt", "decrypt"].map((option) => (
//             <button
//               key={option}
//               onClick={() => switchMode(option)}
//               style={{
//                 flex: 1,
//                 padding: "9px 0",
//                 border: "none",
//                 borderRadius: 7,
//                 fontSize: 13.5,
//                 fontWeight: 600,
//                 cursor: "pointer",
//                 background: mode === option ? "#2F9E76" : "transparent",
//                 color: mode === option ? "#FFFFFF" : "#6B7684",
//               }}
//             >
//               {option === "encrypt" ? "Encrypt" : "Decrypt"}
//             </button>
//           ))}
//         </div>

//         <div
//           onClick={() => fileInputRef.current?.click()}
//           onDragOver={(event) => {
//             event.preventDefault();
//             setDragging(true);
//           }}
//           onDragLeave={() => setDragging(false)}
//           onDrop={onDrop}
//           style={{
//             border: `1.5px solid ${dragging ? "#2F9E76" : "#D8DCE1"}`,
//             background: dragging ? "rgba(47,158,118,0.05)" : "transparent",
//             borderRadius: 12,
//             padding: "24px 16px",
//             textAlign: "center",
//             cursor: "pointer",
//             marginBottom: 18,
//           }}
//         >
//           <input ref={fileInputRef} type="file" multiple style={{ display: "none" }} onChange={(event) => handleFiles(event.target.files)} />
//           <div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13, wordBreak: "break-all" }}>
//             {files.length ? `${files.length} file${files.length > 1 ? "s" : ""} selected` : "Drop a file here, or click to browse"}
//           </div>
//           {files.length > 0 && (
//             <div style={{ color: "#6B7684", fontSize: 12, marginTop: 6, maxHeight: 54, overflowY: "auto" }}>
//               {files.map((fileItem) => (
//                 <div key={`${fileItem.name}-${fileItem.size}-${fileItem.lastModified}`} style={{ marginTop: 2 }}>
//                   • {fileItem.name}
//                 </div>
//               ))}
//             </div>
//           )}
//           <div style={{ color: "#6B7684", fontSize: 12.5, marginTop: 4 }}>
//             {isEncrypt ? "Any file type — stays on this device" : "Select one or more .vault files created by this app"}
//           </div>
//         </div>

//         <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 18 }}>
//           <button type="button" onClick={() => fileInputRef.current?.click()} style={{ height: 40, border: "1px solid #E2E6EA", background: "#F8F9FA", color: "#6B7684", borderRadius: 9, padding: "0 12px", fontSize: 12.5, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
//             Add files
//           </button>
//           <button type="button" onClick={resetAll} style={{ height: 40, border: "1px solid #E2E6EA", background: "#F8F9FA", color: "#6B7684", borderRadius: 9, padding: "0 12px", fontSize: 12.5, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
//             Remove selected files
//           </button>
//         </div>

//         <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "#6B7684", marginBottom: 6 }}>
//           Password
//         </label>
//         <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
//           <input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter a strong password" autoComplete="off" style={styles.input} />
//           <button type="button" onClick={() => setShowPassword((value) => !value)} title={showPassword ? "Hide password" : "Show password"} style={{ width: 42, background: "#F8F9FA", border: "1px solid #E2E6EA", borderRadius: 9, color: "#6B7684", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
//             {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
//           </button>
//         </div>

//         <button
//           onClick={runAction}
//           disabled={!canSubmit}
//           style={{
//             ...styles.actionButton,
//             cursor: canSubmit ? "pointer" : "not-allowed",
//             background: !canSubmit ? "#EEF0F2" : isEncrypt ? "#2F9E76" : "#C68A2E",
//             color: !canSubmit ? "#9AA3AF" : "#FFFFFF",
//           }}
//         >
//           {busy ? "Working…" : isEncrypt ? "Encrypt File" : "Decrypt File"}
//         </button>

//         {status.text && (
//           <div style={{ marginTop: 14, fontSize: 13, display: "flex", alignItems: "center", gap: 6, color: status.type === "error" ? "#C13F3F" : "#6B7684" }}>
//             {status.type === "error" && <ShieldAlert size={14} />}
//             {status.type === "success" && <ShieldCheck size={14} />}
//             {status.text}
//           </div>
//         )}

//         {showSuccessModal && downloadLinks.length > 0 && (
//           <div style={{ position: "fixed", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: 16, background: "rgba(27, 34, 44, 0.35)", zIndex: 50 }} onClick={() => setShowSuccessModal(false)}>
//             <div style={{ width: "100%", maxWidth: 360, background: "#FFFFFF", border: "1px solid #E2E6EA", borderRadius: 14, padding: 18, boxShadow: "0 18px 36px -22px rgba(27,34,44,0.28)", position: "relative" }} onClick={(event) => event.stopPropagation()}>
//               <button type="button" onClick={() => setShowSuccessModal(false)} style={{ position: "absolute", top: 10, right: 10, border: "none", background: "transparent", color: "#6B7684", cursor: "pointer", fontSize: 18, lineHeight: 1 }} aria-label="Close success dialog">
//                 ×
//               </button>

//               <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
//                 <ShieldCheck size={16} color="#2F9E76" />
//                 <div style={{ fontSize: 15, fontWeight: 700, color: "#1B222C" }}>
//                   {isEncrypt ? "Files encrypted successfully" : "Files decrypted successfully"}
//                 </div>
//               </div>

//               <div style={{ fontSize: 13, color: "#6B7684", marginBottom: 14 }}>
//                 {downloadLinks.length} result file{downloadLinks.length > 1 ? "s" : ""} are ready to download.
//               </div>

//               <div style={{ display: "grid", gap: 8 }}>
//                 {downloadLinks.map((item) => (
//                   <a key={`${item.name}-${item.url}`} href={item.url} download={item.name} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6, padding: "10px 0", borderRadius: 9, border: "1px solid #2F9E76", color: "#2F9E76", textDecoration: "none", fontSize: 13.5, fontWeight: 600 }}>
//                     <Download size={15} />
//                     {item.name}
//                   </a>
//                 ))}
//               </div>
//             </div>
//           </div>
//         )}

//         <div style={{ marginTop: 20, fontSize: 11.5, color: "#9AA3AF", lineHeight: 1.5, borderTop: "1px solid #EEF0F2", paddingTop: 14 }} />
//       </div>
//     </div>
//   );
// }



// Vault.jsx — single-file, 100% in-browser file encryption (AES-256-GCM + PBKDF2) with GSAP animations.
// Needs only:  lucide-react  (react / react-dom already in your project). GSAP is loaded from cdnjs at runtime,
// so there is nothing else to install. If the CDN is unreachable the app still works, just without animations.
// No login, no database, no Tailwind. History is kept only in this browser (localStorage).




//GREEN THEME WEBSITE 




// import React, { useState, useRef, useEffect, useLayoutEffect, useMemo, useCallback } from "react";
// import {
//   Lock, Unlock, Eye, EyeOff, Download, ShieldCheck, Upload, FileText, X, Trash2, Copy, Check,
//   Sparkles, Moon, Sun, History, Loader2, FileArchive, KeyRound, WifiOff, Cpu, AlertTriangle,
// } from "lucide-react";

// /* ───────────────────────── GSAP loader (CDN, with a silent no-op fallback) ───────────────────────── */
// const GSAP_CDN = "https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/";
// const NOOP = new Proxy(function () {}, { get: (_, k) => (k === "then" ? undefined : NOOP), apply: () => NOOP });
// let gsap, ScrollTrigger, animated = false, gsapPromise;
// const loadScript = (src) => new Promise((resolve, reject) => {
//   const old = document.querySelector(`script[src="${src}"]`);
//   if (old && old.dataset.ok) return resolve();
//   const el = old || document.createElement("script");
//   el.src = src;
//   el.addEventListener("load", () => { el.dataset.ok = "1"; resolve(); });
//   el.addEventListener("error", () => reject(new Error(`Could not load ${src}`)));
//   if (!old) document.head.appendChild(el);
// });
// function loadGsap() {
//   gsapPromise = gsapPromise || loadScript(`${GSAP_CDN}gsap.min.js`)
//     .then(() => loadScript(`${GSAP_CDN}ScrollTrigger.min.js`))
//     .then(() => {
//       gsap = window.gsap; ScrollTrigger = window.ScrollTrigger;
//       gsap.registerPlugin(ScrollTrigger); animated = true;
//     })
//     .catch(() => { gsap = NOOP; ScrollTrigger = NOOP; animated = false; });
//   return gsapPromise;
// }

// /* ───────────────────────── Crypto (format unchanged: base64 "VLT1"+salt16+iv12+AES-GCM) ───────────────────────── */
// const MAGIC = new TextEncoder().encode("VLT1");
// const ITER = 250000;
// const LARGE = 100 * 1024 * 1024;
// const tick = () => new Promise((r) => setTimeout(r, 0));
// const cat = (parts) => {
//   const out = new Uint8Array(parts.reduce((s, p) => s + p.byteLength, 0));
//   let n = 0;
//   parts.forEach((p) => { out.set(p, n); n += p.byteLength; });
//   return out;
// };
// const toB64 = (bytes) => {
//   let s = "";
//   for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
//   return btoa(s);
// };
// const fromB64 = (v) => Uint8Array.from(atob(v.replace(/\s/g, "")), (c) => c.charCodeAt(0));
// const hasMagic = (b) => MAGIC.every((v, i) => b[i] === v);

// async function deriveKey(password, salt) {
//   const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
//   return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
// }

// async function encryptFile(file, password, on) {
//   on(8, "Reading file…"); await tick();
//   const data = new Uint8Array(await file.arrayBuffer());
//   const nameB = new TextEncoder().encode(file.name);
//   const mimeB = new TextEncoder().encode(file.type || "application/octet-stream");
//   if (nameB.length > 0xffff || mimeB.length > 255) throw new Error("File name or type is too long.");
//   const head = new Uint8Array(2 + nameB.length + 1 + mimeB.length);
//   new DataView(head.buffer).setUint16(0, nameB.length, true);
//   head.set(nameB, 2); head[2 + nameB.length] = mimeB.length; head.set(mimeB, 3 + nameB.length);
//   on(25, "Deriving key…"); await tick();
//   const salt = crypto.getRandomValues(new Uint8Array(16));
//   const iv = crypto.getRandomValues(new Uint8Array(12));
//   const key = await deriveKey(password, salt);
//   on(65, "Encrypting…"); await tick();
//   const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, cat([head, data])));
//   on(95, "Packaging…"); await tick();
//   return { blob: new Blob([toB64(cat([MAGIC, salt, iv, cipher]))], { type: "text/plain" }), name: `${file.name}.vault` };
// }

// async function decryptFile(file, password, on) {
//   on(8, "Reading file…"); await tick();
//   const raw = new Uint8Array(await file.arrayBuffer());
//   let buf = raw;
//   if (!hasMagic(raw)) {
//     try {
//       const txt = new TextDecoder().decode(raw);
//       if (/^[A-Za-z0-9+/\s]+=*\s*$/.test(txt)) buf = fromB64(txt);
//     } catch { buf = raw; }
//   }
//   if (buf.length < 48 || !hasMagic(buf)) throw new Error("This doesn't look like a Vault-encrypted file.");
//   on(30, "Deriving key…"); await tick();
//   const key = await deriveKey(password, buf.slice(4, 20));
//   on(70, "Decrypting…"); await tick();
//   let p;
//   try { p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(20, 32) }, key, buf.slice(32))); }
//   catch { throw new Error("Wrong password, or the file is corrupted."); }
//   const nl = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint16(0, true);
//   const name = new TextDecoder().decode(p.slice(2, 2 + nl));
//   const ml = p[2 + nl];
//   const mime = new TextDecoder().decode(p.slice(3 + nl, 3 + nl + ml));
//   return { blob: new Blob([p.slice(3 + nl + ml)], { type: mime }), name: name || "decrypted-file" };
// }

// /* ───────────────────────── Helpers ───────────────────────── */
// const COMMON = ["password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin", "iloveyou", "111111", "password1"];
// function strength(p) {
//   if (!p) return { s: 0, l: "", h: "" };
//   const cls = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
//   if (COMMON.includes(p.toLowerCase()) || /^(.)\1+$/.test(p)) return { s: 0, l: "Very weak", h: "Very common password." };
//   let s = (p.length >= 8) + (p.length >= 12) + (p.length >= 16) + (cls >= 3);
//   if (p.length < 8) s = Math.min(s, 1);
//   if (cls === 1) s = Math.min(s, 2);
//   return { s, l: ["Very weak", "Weak", "Fair", "Good", "Strong"][s], h: p.length < 12 ? "Aim for 12+ characters." : cls < 3 ? "Mix cases, numbers & symbols." : "" };
// }
// const rnd = (max) => {
//   const lim = Math.floor(0x100000000 / max) * max, b = new Uint32Array(1);
//   do crypto.getRandomValues(b); while (b[0] >= lim);
//   return b[0] % max;
// };
// function genPw(len = 20) {
//   const sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"];
//   const all = sets.join("");
//   const c = sets.map((s) => s[rnd(s.length)]);
//   while (c.length < len) c.push(all[rnd(all.length)]);
//   for (let i = c.length - 1; i > 0; i--) { const j = rnd(i + 1); [c[i], c[j]] = [c[j], c[i]]; }
//   return c.join("");
// }
// const fmtBytes = (n) => {
//   if (!n) return "0 B";
//   const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 3);
//   const v = n / 1024 ** i;
//   return `${v >= 10 || !i ? Math.round(v) : v.toFixed(1)} ${["B", "KB", "MB", "GB"][i]}`;
// };
// const ago = (t) => {
//   const m = Math.round((Date.now() - t) / 60000);
//   if (m < 1) return "just now";
//   if (m < 60) return `${m} min ago`;
//   if (m < 1440) return `${Math.round(m / 60)} h ago`;
//   return new Date(t).toLocaleDateString();
// };
// const save = (blob, name) => {
//   const u = URL.createObjectURL(blob), a = document.createElement("a");
//   a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove();
//   setTimeout(() => URL.revokeObjectURL(u), 1500);
// };
// const ls = {
//   get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
//   set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
// };

// // tiny store-only ZIP writer (no dependency)
// const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
// const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
// async function makeZip(entries) {
//   const enc = new TextEncoder(), seen = {}, parts = [], cen = [];
//   let off = 0;
//   for (const e of entries) {
//     const k = (seen[e.name] = (seen[e.name] || 0) + 1);
//     const nm = k > 1 ? e.name.replace(/(\.[^.]*)?$/, ` (${k - 1})$1`) : e.name;
//     const nb = enc.encode(nm.replace(/[\\/]/g, "_")), d = new Uint8Array(await e.blob.arrayBuffer()), crc = crc32(d);
//     const l = new Uint8Array(30 + nb.length), lv = new DataView(l.buffer);
//     lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0x800, true); lv.setUint16(12, 0x21, true);
//     lv.setUint32(14, crc, true); lv.setUint32(18, d.length, true); lv.setUint32(22, d.length, true); lv.setUint16(26, nb.length, true); l.set(nb, 30);
//     const h = new Uint8Array(46 + nb.length), hv = new DataView(h.buffer);
//     hv.setUint32(0, 0x02014b50, true); hv.setUint16(4, 20, true); hv.setUint16(6, 20, true); hv.setUint16(8, 0x800, true); hv.setUint16(14, 0x21, true);
//     hv.setUint32(16, crc, true); hv.setUint32(20, d.length, true); hv.setUint32(24, d.length, true); hv.setUint16(28, nb.length, true); hv.setUint32(42, off, true); h.set(nb, 46);
//     parts.push(l, d); cen.push(h); off += l.length + d.length;
//   }
//   const end = new Uint8Array(22), ev = new DataView(end.buffer);
//   ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
//   ev.setUint32(12, cen.reduce((s, c) => s + c.length, 0), true); ev.setUint32(16, off, true);
//   return new Blob([...parts, ...cen, end], { type: "application/zip" });
// }

// /* ───────────────────────── GSAP-powered small components ───────────────────────── */
// function Magnetic({ children }) {
//   const r = useRef(null);
//   const move = (e) => {
//     const b = r.current.getBoundingClientRect();
//     gsap.to(r.current, { x: (e.clientX - b.left - b.width / 2) * 0.25, y: (e.clientY - b.top - b.height / 2) * 0.35, duration: 0.3 });
//   };
//   const leave = () => gsap.to(r.current, { x: 0, y: 0, duration: 0.8, ease: "elastic.out(1,.4)" });
//   return <span ref={r} onMouseMove={move} onMouseLeave={leave} style={{ display: "inline-block" }}>{children}</span>;
// }

// function CountUp({ to }) {
//   const el = useRef(null), v = useRef({ n: 0 });
//   useEffect(() => {
//     if (!animated) { if (el.current) el.current.textContent = to; return undefined; }
//     const tw = gsap.to(v.current, { n: to, duration: 1, ease: "power2.out", onUpdate: () => { if (el.current) el.current.textContent = Math.round(v.current.n); } });
//     return () => tw.kill();
//   }, [to]);
//   return <span ref={el}>0</span>;
// }

// const PLAIN = "Q3 revenue: $4.2M · CONFIDENTIAL";
// const CIPHER = "VkxUMa7Fq9+Zr3Lx0TnB8cE2dYw5Hs/KmP1uJvQeGo4A";
// const NOISE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// function CipherDemo() {
//   const pre = useRef(null), label = useRef(null), pill = useRef(null);
//   useEffect(() => {
//     const st = { p: 1 };
//     const render = (t, p) => { if (pre.current) pre.current.textContent = [...t].map((c, i) => (i < p * t.length ? c : NOISE[rnd(NOISE.length)])).join(""); };
//     render(PLAIN, 1);
//     const mm = gsap.matchMedia();
//     mm.add("(prefers-reduced-motion: no-preference)", () => {
//       const tl = gsap.timeline({ repeat: -1 });
//       [true, false].forEach((enc) => {
//         tl.call(() => {
//           if (label.current) label.current.textContent = enc ? "Q3-financials.xlsx.vault" : "Q3-financials.xlsx";
//           if (pill.current) { pill.current.textContent = enc ? "Encrypted" : "Plain"; pill.current.className = `pill ${enc ? "g" : "a"}`; }
//         })
//           .fromTo(st, { p: 0 }, { p: 1, duration: 1.4, ease: "power2.inOut", onUpdate: () => render(enc ? CIPHER : PLAIN, st.p) })
//           .to({}, { duration: 2.2 });
//       });
//     });
//     return () => mm.revert();
//   }, []);
//   return (
//     <div className="demo card">
//       <div className="bar"><i /><i /><i /><small>vault · in your browser</small></div>
//       <div className="dbody">
//         <div className="dfile"><FileText size={20} /><strong ref={label}>Q3-financials.xlsx</strong><span ref={pill} className="pill a">Plain</span></div>
//         <pre ref={pre} className="dtext" aria-hidden="true" />
//         <div className="dkey"><KeyRound size={14} /> ••••••••••••</div>
//       </div>
//     </div>
//   );
// }

// function FileRow({ it, onRemove, disabled }) {
//   const row = useRef(null), bar = useRef(null);
//   useLayoutEffect(() => { gsap.from(row.current, { x: -24, opacity: 0, duration: 0.45, ease: "power3.out" }); }, []);
//   useEffect(() => { gsap.to(bar.current, { width: `${it.pct}%`, duration: 0.4, ease: "power2.out" }); }, [it.pct]);
//   return (
//     <div ref={row} className={`frow ${it.status}`}>
//       <span className="fico">{it.file.name.endsWith(".vault") ? <Lock size={17} /> : <FileText size={17} />}</span>
//       <div className="finfo">
//         <div className="fname" title={it.file.name}>{it.file.name}</div>
//         <div className="fsub">
//           {fmtBytes(it.file.size)}
//           {it.file.size > LARGE && <b className="warn"><AlertTriangle size={12} /> Large file</b>}
//           {it.status !== "idle" && <span className={it.status === "error" ? "err" : ""}> · {it.msg}</span>}
//         </div>
//         {(it.status === "work" || it.status === "done") && <div className="prog"><span ref={bar} /></div>}
//       </div>
//       {it.status === "work" ? <Loader2 size={17} className="spin" /> : it.status === "done" ? <Check size={17} className="okc" /> : (
//         <button className="ib" onClick={onRemove} disabled={disabled} aria-label={`Remove ${it.file.name}`}><X size={16} /></button>
//       )}
//     </div>
//   );
// }

// function DoneModal({ results, isEnc, onClose, onZip, zipping }) {
//   const root = useRef(null);
//   useLayoutEffect(() => {
//     const prev = document.activeElement, ovf = document.body.style.overflow;
//     document.body.style.overflow = "hidden";
//     root.current.querySelector("button")?.focus();
//     const key = (e) => e.key === "Escape" && onClose();
//     document.addEventListener("keydown", key);
//     const ctx = gsap.context(() => {
//       gsap.timeline()
//         .from(".mbg", { opacity: 0, duration: 0.25 })
//         .from(".mcard", { scale: 0.85, y: 30, opacity: 0, duration: 0.5, ease: "back.out(1.7)" }, "<")
//         .fromTo(".mcirc", { strokeDashoffset: 151 }, { strokeDashoffset: 0, duration: 0.6, ease: "power2.out" }, "-=.2")
//         .fromTo(".mtick", { strokeDashoffset: 40 }, { strokeDashoffset: 0, duration: 0.4 }, "-=.1")
//         .from(".mrow", { x: -20, opacity: 0, stagger: 0.07, duration: 0.35 }, "-=.2");
//     }, root);
//     return () => { ctx.revert(); document.removeEventListener("keydown", key); document.body.style.overflow = ovf; prev?.focus?.(); };
//   }, []); // eslint-disable-line
//   return (
//     <div ref={root}>
//       <div className="mbg" onMouseDown={onClose}>
//         <div className="mcard" role="dialog" aria-modal="true" aria-label="Results ready" onMouseDown={(e) => e.stopPropagation()}>
//           <button className="ib mx" onClick={onClose} aria-label="Close"><X size={18} /></button>
//           <svg className="check" viewBox="0 0 52 52" aria-hidden="true"><circle className="mcirc" cx="26" cy="26" r="24" /><path className="mtick" d="M15 27l8 8 14-16" /></svg>
//           <h3>{isEnc ? "Files encrypted" : "Files decrypted"}</h3>
//           <p className="mu">{results.length} file{results.length > 1 ? "s" : ""} ready. Nothing was uploaded. Downloads are cleared when you close this.</p>
//           <div className="dls">
//             {results.map((r) => (
//               <a key={r.url} className="btn out block mrow" href={r.url} download={r.name}><Download size={16} /><span>{r.name}</span></a>
//             ))}
//           </div>
//           {results.length > 1 && (
//             <button className="btn pri block" onClick={onZip} disabled={zipping}>{zipping ? <Loader2 size={16} className="spin" /> : <FileArchive size={16} />} Download all as ZIP</button>
//           )}
//         </div>
//       </div>
//     </div>
//   );
// }

// /* ───────────────────────── Main component ───────────────────────── */
// let uid = 0;
// function VaultApp() {
//   const root = useRef(null), input = useRef(null), dz = useRef(null), toastEl = useRef(null), first = useRef(true), resRef = useRef([]);
//   const [dark, setDark] = useState(() => ls.get("vault.dark", window.matchMedia?.("(prefers-color-scheme: dark)").matches));
//   const [mode, setMode] = useState("encrypt");
//   const [items, setItems] = useState([]);
//   const [pw, setPw] = useState("");
//   const [show, setShow] = useState(false);
//   const [copied, setCopied] = useState(false);
//   const [drag, setDrag] = useState(false);
//   const [busy, setBusy] = useState(false);
//   const [results, setResults] = useState([]);
//   const [zipping, setZipping] = useState(false);
//   const [hist, setHist] = useState(() => ls.get("vault.history", []));
//   const [toast, setToast] = useState(null);

//   const enc = mode === "encrypt";
//   const st = useMemo(() => strength(pw), [pw]);
//   const can = items.length > 0 && pw.length > 0 && !busy;
//   const stats = useMemo(() => ({
//     e: hist.filter((h) => h.op === "encrypt" && h.ok).length,
//     d: hist.filter((h) => h.op === "decrypt" && h.ok).length,
//     last: hist[0]?.t,
//   }), [hist]);
//   resRef.current = results;

//   const say = useCallback((m, bad) => setToast({ m, bad, id: Date.now() }), []);
//   const patch = (id, p) => setItems((l) => l.map((i) => (i.id === id ? { ...i, ...p } : i)));
//   const dropResults = useCallback(() => { resRef.current.forEach((r) => URL.revokeObjectURL(r.url)); setResults([]); }, []);
//   useEffect(() => () => resRef.current.forEach((r) => URL.revokeObjectURL(r.url)), []);
//   useEffect(() => ls.set("vault.dark", dark), [dark]);

//   useEffect(() => {
//     if (!toast) return undefined;
//     if (!animated) { const t0 = setTimeout(() => setToast(null), 3800); return () => clearTimeout(t0); }
//     gsap.fromTo(toastEl.current, { y: 30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, ease: "back.out(1.6)" });
//     const t = setTimeout(() => gsap.to(toastEl.current, { y: 20, opacity: 0, duration: 0.3, onComplete: () => setToast(null) }), 3800);
//     return () => clearTimeout(t);
//   }, [toast]);

//   // intro + scroll animations
//   useLayoutEffect(() => {
//     const ctx = gsap.context(() => {
//       const mm = gsap.matchMedia();
//       mm.add("(prefers-reduced-motion: no-preference)", () => {
//         gsap.timeline({ defaults: { ease: "power3.out" } })
//           .from(".nav", { yPercent: -100, opacity: 0, duration: 0.7 })
//           .from(".badge", { y: 16, opacity: 0, duration: 0.5 }, "-=.3")
//           .from(".h1 .w span", { yPercent: 115, duration: 0.9, stagger: 0.08 }, "-=.3")
//           .from(".lead, .cta > *, .trust li", { y: 20, opacity: 0, duration: 0.6, stagger: 0.08 }, "-=.5")
//           .from(".demo", { y: 60, opacity: 0, rotateX: -12, transformPerspective: 900, duration: 1 }, "-=1");
//         gsap.to(".orb.a", { x: 70, y: 40, duration: 7, yoyo: true, repeat: -1, ease: "sine.inOut" });
//         gsap.to(".orb.b", { x: -60, y: -50, duration: 9, yoyo: true, repeat: -1, ease: "sine.inOut" });
//         gsap.utils.toArray(".reveal").forEach((el) => gsap.from(el, { y: 40, opacity: 0, duration: 0.8, ease: "power3.out", scrollTrigger: { trigger: el, start: "top 88%" } }));
//         gsap.set(".feat", { opacity: 0, y: 40 });
//         ScrollTrigger.batch(".feat", { start: "top 92%", once: true, onEnter: (b) => gsap.to(b, { opacity: 1, y: 0, stagger: 0.1, duration: 0.7, ease: "power3.out" }) });
//       });
//     }, root);
//     return () => ctx.revert();
//   }, []);

//   // mode-switch + drag animations
//   useEffect(() => {
//     if (first.current) { first.current = false; return; }
//     gsap.fromTo(".swap", { y: 12, opacity: 0.3 }, { y: 0, opacity: 1, duration: 0.45, stagger: 0.06, ease: "power3.out" });
//   }, [mode]);
//   useEffect(() => { gsap.to(dz.current, { scale: drag ? 1.02 : 1, duration: 0.25, ease: "power2.out" }); }, [drag]);

//   const addFiles = (list) => {
//     const sel = Array.from(list || []);
//     if (!sel.length) return;
//     dropResults();
//     setItems((cur) => {
//       const seen = new Set(cur.map((i) => i.key)), next = [...cur];
//       sel.forEach((f) => {
//         const key = `${f.name}-${f.size}-${f.lastModified}`;
//         if (!seen.has(key)) { seen.add(key); next.push({ id: `f${++uid}`, key, file: f, status: "idle", pct: 0, msg: "" }); }
//       });
//       return next;
//     });
//     if (sel.some((f) => f.size > LARGE)) say("Files over 100 MB are processed in memory and may be slow.");
//   };

//   const switchMode = (m) => { if (busy || m === mode) return; setMode(m); setItems([]); dropResults(); };

//   const run = async () => {
//     if (!can) return;
//     setBusy(true); dropResults();
//     const out = [], log = [];
//     for (const it of items) {
//       patch(it.id, { status: "work", pct: 3, msg: "Starting…" });
//       try {
//         const r = await (enc ? encryptFile : decryptFile)(it.file, pw, (pct, msg) => patch(it.id, { pct, msg }));
//         out.push({ ...r, url: URL.createObjectURL(r.blob) });
//         patch(it.id, { status: "done", pct: 100, msg: "Done" });
//         log.push({ id: `${Date.now()}-${log.length}`, op: mode, name: it.file.name, size: it.file.size, ok: true, t: Date.now() });
//       } catch (e) {
//         patch(it.id, { status: "error", pct: 0, msg: e.message || "Something went wrong." });
//         log.push({ id: `${Date.now()}-${log.length}`, op: mode, name: it.file.name, size: it.file.size, ok: false, t: Date.now() });
//       }
//     }
//     if (out.length) { setResults(out); setPw(""); say(`${out.length} file${out.length > 1 ? "s" : ""} ${enc ? "encrypted" : "decrypted"}.`); }
//     if (out.length < items.length) say(`${items.length - out.length} file(s) failed. See the list.`, true);
//     setItems((l) => l.filter((i) => i.status === "error"));
//     setHist((h) => { const n = [...log.reverse(), ...h].slice(0, 200); ls.set("vault.history", n); return n; });
//     setBusy(false);
//   };

//   const zip = async () => {
//     setZipping(true);
//     try { save(await makeZip(results), `vault-${Date.now()}.zip`); } catch { say("Could not create ZIP.", true); }
//     setZipping(false);
//   };

//   const copy = async () => {
//     try { await navigator.clipboard.writeText(pw); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch { say("Clipboard blocked.", true); }
//   };

//   const delHist = (id) => setHist((h) => { const n = h.filter((x) => x.id !== id); ls.set("vault.history", n); return n; });
//   const clearHist = () => { setHist([]); ls.set("vault.history", []); say("History cleared."); };
//   const go = (id) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });

//   return (
//     <div ref={root} className={`vt ${dark ? "dark" : ""}`}>
//       <style>{CSS}</style>
//       <div className="orb a" /><div className="orb b" />

//       <header className="nav">
//         <div className="wrap navin">
//           <span className="logo"><span className="lm"><Lock size={16} strokeWidth={2.4} /></span>Vault</span>
//           <nav className="links"><button onClick={() => go("vault")}>Workspace</button><button onClick={() => go("history")}>History</button><button onClick={() => go("security")}>Security</button></nav>
//           <button className="ib bx" onClick={() => setDark((d) => !d)} aria-label="Toggle theme">{dark ? <Sun size={18} /> : <Moon size={18} />}</button>
//         </div>
//       </header>

//       <main>
//         <section className="wrap hero">
//           <div className="hcopy">
//             <span className="badge"><ShieldCheck size={14} /> Zero-knowledge · 100% in your browser</span>
//             <h1 className="h1">
//               {["Encrypt", "anything."].map((w) => <span className="w" key={w}><span>{w}</span></span>)}<br />
//               {["Trust", "no", "server."].map((w) => <span className="w grad" key={w}><span>{w}</span></span>)}
//             </h1>
//             <p className="lead">Lock files with AES-256-GCM directly on your device. No account, no uploads, no database. Your files and passwords never leave this tab.</p>
//             <div className="cta">
//               <Magnetic><button className="btn pri lg" onClick={() => go("vault")}>Start encrypting <Sparkles size={18} /></button></Magnetic>
//               <Magnetic><button className="btn out lg" onClick={() => go("security")}>How it's secured</button></Magnetic>
//             </div>
//             <ul className="trust"><li><Lock size={14} /> AES-256-GCM</li><li><WifiOff size={14} /> Works offline</li><li><Cpu size={14} /> PBKDF2 · 250k rounds</li></ul>
//           </div>
//           <CipherDemo />
//         </section>

//         <section id="vault" className="wrap sec" data-mode={mode}>
//           <div className="stats reveal">
//             <div className="card stat"><span className="si g"><Lock size={18} /></span><div><small>Files encrypted</small><b><CountUp to={stats.e} /></b></div></div>
//             <div className="card stat"><span className="si a"><Unlock size={18} /></span><div><small>Files decrypted</small><b><CountUp to={stats.d} /></b></div></div>
//             <div className="card stat"><span className="si"><History size={18} /></span><div><small>Last activity</small><b className="sm">{stats.last ? ago(stats.last) : "No activity yet"}</b></div></div>
//           </div>

//           <div className="card work reveal">
//             <div className="seg" role="group" aria-label="Mode">
//               {["encrypt", "decrypt"].map((m) => (
//                 <button key={m} className={mode === m ? "on" : ""} aria-pressed={mode === m} onClick={() => switchMode(m)} disabled={busy}>
//                   {m === "encrypt" ? <Lock size={15} /> : <Unlock size={15} />}{m === "encrypt" ? "Encrypt" : "Decrypt"}
//                 </button>
//               ))}
//             </div>

//             <div ref={dz} className={`dz swap ${drag ? "drag" : ""}`} role="button" tabIndex={0} aria-label="Choose files or drop them here"
//               onClick={() => input.current?.click()}
//               onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
//               onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
//               onDrop={(e) => { e.preventDefault(); setDrag(false); addFiles(e.dataTransfer.files); }}>
//               <input ref={input} type="file" multiple hidden onChange={(e) => { addFiles(e.target.files); e.target.value = ""; }} />
//               <span className="dico"><Upload size={22} /></span>
//               <strong>{drag ? "Drop to add files" : "Drop files here, or click to browse"}</strong>
//               <span className="mu sm">{enc ? "Any file type · stays on this device" : "Select .vault files created by this app"}</span>
//             </div>

//             {items.length > 0 && (
//               <div className="flist">
//                 <div className="fhead"><span>{items.length} file{items.length > 1 ? "s" : ""} selected</span><button className="lnk" onClick={() => setItems([])} disabled={busy}>Clear all</button></div>
//                 {items.map((it) => <FileRow key={it.id} it={it} disabled={busy} onRemove={() => setItems((l) => l.filter((x) => x.id !== it.id))} />)}
//               </div>
//             )}

//             <div className="field swap">
//               <label htmlFor="pw">Password</label>
//               <div className="irow">
//                 <input id="pw" className="inp" type={show ? "text" : "password"} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="off"
//                   placeholder={enc ? "Choose a strong password" : "Password used to encrypt"} />
//                 <button className="ib bx" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
//                 {enc && <button className="ib bx" onClick={() => { setPw(genPw(20)); setShow(true); }} aria-label="Generate strong password" title="Generate"><Sparkles size={17} /></button>}
//                 {enc && <button className="ib bx" onClick={copy} disabled={!pw} aria-label="Copy password">{copied ? <Check size={17} /> : <Copy size={17} />}</button>}
//               </div>
//               {enc && pw && (
//                 <div className="meter">
//                   <div className={`bars s${st.s}`}>{[0, 1, 2, 3, 4].map((i) => <span key={i} className={i <= st.s ? "on" : ""} />)}</div>
//                   <small className="mu">{st.l}{st.h ? ` · ${st.h}` : ""}</small>
//                 </div>
//               )}
//             </div>

//             <p className="note swap"><ShieldCheck size={15} /><span><b>Zero-knowledge:</b> your password and files never leave this device, so a lost password can't be recovered. Store it safely.</span></p>

//             <button className="btn pri lg block swap" onClick={run} disabled={!can}>
//               {busy ? <><Loader2 size={18} className="spin" /> Working…</> : <>{enc ? <Lock size={18} /> : <Unlock size={18} />} {enc ? "Encrypt" : "Decrypt"} {items.length > 1 ? `${items.length} files` : "file"}</>}
//             </button>
//           </div>
//         </section>

//         <section id="history" className="wrap sec">
//           <div className="hrow reveal">
//             <div><h2>History</h2><p className="mu sm">Stored only in this browser: file name, size and time. Never contents or passwords.</p></div>
//             <button className="btn dng sm" onClick={clearHist} disabled={!hist.length}><Trash2 size={15} /> Clear</button>
//           </div>
//           <div className="card hist reveal">
//             {hist.length === 0 ? <div className="empty"><History size={30} /><p className="mu">No activity yet. Encrypt or decrypt a file and it appears here.</p></div> : (
//               <ul>{hist.slice(0, 30).map((h) => (
//                 <li key={h.id}>
//                   <span className={`si ${h.op === "encrypt" ? "g" : "a"}`}>{h.op === "encrypt" ? <Lock size={15} /> : <Unlock size={15} />}</span>
//                   <div className="hn"><b title={h.name}>{h.name}</b><small className="mu">{fmtBytes(h.size)} · {ago(h.t)}</small></div>
//                   <span className={`pill ${h.ok ? "g" : "r"}`}>{h.ok ? (h.op === "encrypt" ? "Encrypted" : "Decrypted") : "Failed"}</span>
//                   <button className="ib" onClick={() => delHist(h.id)} aria-label={`Delete ${h.name} from history`}><Trash2 size={15} /></button>
//                 </li>
//               ))}</ul>
//             )}
//           </div>
//         </section>

//         <section id="security" className="wrap sec">
//           <h2 className="ctr reveal">Security you can verify</h2>
//           <p className="mu ctr reveal" style={{ marginBottom: 28 }}>Standard, well-reviewed primitives. Nothing exotic.</p>
//           <div className="feats">
//             {[[ShieldCheck, "AES-256-GCM", "Authenticated encryption detects tampering and wrong passwords."],
//               [Cpu, "PBKDF2 · 250,000 rounds", "SHA-256 key derivation with a fresh random salt for every file."],
//               [WifiOff, "Local-only", "Runs on the Web Crypto API. Files and passwords never touch a server."],
//               [KeyRound, "Password generator", "Unbiased secure randomness and a live strength meter."],
//               [FileArchive, "Batch & ZIP", "Process many files at once and grab everything as one ZIP."],
//               [History, "Private history", "Kept in your own browser storage. Clear it any time."]].map(([I, t, d]) => (
//               <div key={t} className="card feat"><span className="si g"><I size={20} /></span><h3>{t}</h3><p className="mu">{d}</p></div>
//             ))}
//           </div>
//         </section>
//       </main>

//       <footer className="wrap foot"><span className="logo"><span className="lm"><Lock size={16} /></span>Vault</span><small className="mu">© {new Date().getFullYear()} Vault · Your data stays yours.</small></footer>

//       {results.length > 0 && <DoneModal results={results} isEnc={enc} zipping={zipping} onZip={zip} onClose={dropResults} />}
//       <div className="toasts" role="status" aria-live="polite">{toast && <div ref={toastEl} key={toast.id} className={`toast ${toast.bad ? "bad" : ""}`}>{toast.m}</div>}</div>
//     </div>
//   );
// }

// /* ───────────────────────── Styles (scoped to .vt) ───────────────────────── */
// const CSS = `
// @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
// .vt{--bg:#f5f7f8;--card:rgba(255,255,255,.76);--solid:#fff;--s2:#f1f3f5;--bd:#e2e6ea;--tx:#1b222c;--mu:#5f6b79;--g:#2f9e76;--gs:#1f7a59;--gl:#eaf6f0;--a:#c68a2e;--as:#956414;--al:#fbf3e4;--r:#c13f3f;--rl:#fbecec;--on:#fff;
//  --ac:var(--g);--acs:var(--gs);--acl:var(--gl);--sh:0 1px 2px rgba(27,34,44,.04),0 18px 40px -24px rgba(27,34,44,.22);
//  font-family:Inter,system-ui,sans-serif;font-size:15px;line-height:1.55;color:var(--tx);background:var(--bg);min-height:100vh;position:relative;overflow-x:hidden;transition:background .3s,color .3s}
// .vt.dark{--bg:#0c1117;--card:rgba(22,29,38,.74);--solid:#141b24;--s2:#1a232e;--bd:#263140;--tx:#e8edf3;--mu:#94a1b1;--g:#3bb98c;--gs:#3bb98c;--gl:rgba(59,185,140,.14);--a:#e0a646;--as:#e0a646;--al:rgba(224,166,70,.14);--r:#ef7b7b;--rl:rgba(239,123,123,.14);--on:#06150f;--sh:0 1px 2px rgba(0,0,0,.3),0 18px 40px -22px rgba(0,0,0,.6)}
// .vt [data-mode=decrypt]{--ac:var(--a);--acs:var(--as);--acl:var(--al)}
// .vt *{box-sizing:border-box}.vt h1,.vt h2,.vt h3,.vt p{margin:0}.vt button{font:inherit;color:inherit;cursor:pointer}.vt :focus-visible{outline:2px solid var(--acs);outline-offset:2px;border-radius:8px}
// .vt .mu{color:var(--mu)}.vt .sm{font-size:13px}.vt .ctr{text-align:center}.vt .spin{animation:vspin .9s linear infinite}@keyframes vspin{to{transform:rotate(360deg)}}
// .vt .orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.28;pointer-events:none;z-index:0}.vt .orb.a{width:480px;height:480px;background:#2f9e76;top:-120px;left:-120px}.vt .orb.b{width:420px;height:420px;background:#c68a2e;bottom:-120px;right:-100px}
// .vt main,.vt .nav,.vt .foot{position:relative;z-index:1}.vt .wrap{max-width:1120px;margin:0 auto;padding:0 20px}
// .vt .card{background:var(--card);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);border:1px solid var(--bd);border-radius:18px;box-shadow:var(--sh)}
// .vt .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 18px;border-radius:12px;border:1px solid transparent;font-weight:600;white-space:nowrap;text-decoration:none;transition:transform .15s,border-color .15s,opacity .15s}
// .vt .btn:hover:not(:disabled){transform:translateY(-1px)}.vt .btn:disabled{opacity:.5;cursor:not-allowed}.vt .lg{padding:13px 22px;border-radius:14px;font-size:15.5px}.vt .block{width:100%}
// .vt .pri{background:var(--acs);color:var(--on);box-shadow:0 10px 22px -12px var(--acs)}.vt .out{background:var(--solid);border-color:var(--bd);color:var(--tx)}.vt .out:hover:not(:disabled){border-color:var(--ac)}.vt .dng{background:var(--rl);color:var(--r)}
// .vt .ib{display:inline-grid;place-items:center;width:38px;height:38px;border:0;border-radius:10px;background:none;color:var(--mu);flex:none;transition:background .15s}.vt .ib:hover:not(:disabled){background:var(--s2);color:var(--tx)}.vt .ib:disabled{opacity:.4}.vt .bx{border:1px solid var(--bd);background:var(--solid)}
// .vt .lnk{background:none;border:0;color:var(--acs);font-weight:600;font-size:13px}
// .vt .nav{position:sticky;top:0;z-index:40;background:var(--card);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}.vt .navin{display:flex;align-items:center;justify-content:space-between;height:64px;gap:16px}
// .vt .links{display:flex;gap:24px;margin-left:auto}.vt .links button{background:none;border:0;color:var(--mu);font-weight:500}.vt .links button:hover{color:var(--tx)}
// .vt .logo{display:inline-flex;align-items:center;gap:10px;font-weight:800;font-size:19px;letter-spacing:-.02em}.vt .lm{width:32px;height:32px;border-radius:10px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,#3bb98c,#1f7a59)}
// .vt .hero{display:grid;grid-template-columns:1.1fr 1fr;gap:48px;align-items:center;padding-top:72px;padding-bottom:56px}.vt .hcopy{display:flex;flex-direction:column;gap:22px}
// .vt .badge{align-self:flex-start;display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:99px;background:var(--gl);color:var(--gs);font-weight:600;font-size:13px}.vt.dark .badge{color:var(--g)}
// .vt .h1{font-size:clamp(38px,5.4vw,62px);font-weight:800;letter-spacing:-.04em;line-height:1.06}.vt .w{display:inline-block;overflow:hidden;vertical-align:top;padding-bottom:.08em;margin-right:.22em}.vt .w span{display:inline-block}
// .vt .grad span{background:linear-gradient(120deg,#2f9e76,#c68a2e);-webkit-background-clip:text;background-clip:text;color:transparent;padding-right:.04em}.vt .lead{font-size:18px;color:var(--mu);max-width:520px}
// .vt .cta{display:flex;gap:12px;flex-wrap:wrap}.vt .trust{list-style:none;margin:0;padding:0;display:flex;gap:18px;flex-wrap:wrap;color:var(--mu);font-size:13.5px}.vt .trust li{display:flex;gap:6px;align-items:center}
// .vt .demo{overflow:hidden}.vt .bar{display:flex;align-items:center;gap:6px;padding:12px 14px;border-bottom:1px solid var(--bd)}.vt .bar i{width:10px;height:10px;border-radius:50%;background:var(--bd)}.vt .bar small{margin-left:8px;color:var(--mu);font-size:12px}
// .vt .dbody{padding:22px;display:flex;flex-direction:column;gap:16px}.vt .dfile{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--bd);border-radius:14px;background:var(--solid)}.vt .dfile strong{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
// .vt .dtext{margin:0;min-height:96px;padding:16px;border-radius:14px;background:var(--s2);font:13px/1.7 'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all}.vt .dkey{font:13px 'JetBrains Mono',monospace;color:var(--mu);display:flex;gap:8px;align-items:center}
// .vt .pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600}.vt .pill.g{background:var(--gl);color:var(--gs)}.vt .pill.a{background:var(--al);color:var(--as)}.vt .pill.r{background:var(--rl);color:var(--r)}.vt.dark .pill.g{color:var(--g)}
// .vt .sec{padding-top:44px;padding-bottom:44px}.vt h2{font-size:clamp(24px,3.2vw,34px);letter-spacing:-.03em}.vt h3{font-size:16px;font-weight:700}
// .vt .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px}.vt .stat{display:flex;gap:14px;align-items:center;padding:16px 18px}.vt .stat small{display:block;font-size:12.5px;font-weight:600;color:var(--mu)}.vt .stat b{font-size:26px;font-weight:800;letter-spacing:-.03em;line-height:1.2}.vt .stat b.sm{font-size:16px;font-weight:700;line-height:1.8}
// .vt .si{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:var(--s2);color:var(--mu);flex:none}.vt .si.g{background:var(--gl);color:var(--g)}.vt .si.a{background:var(--al);color:var(--a)}
// .vt .work{max-width:760px;margin:0 auto;padding:24px;display:flex;flex-direction:column;gap:18px}
// .vt .seg{display:flex;gap:4px;padding:4px;background:var(--s2);border:1px solid var(--bd);border-radius:13px}.vt .seg button{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:9px;border:0;border-radius:10px;background:none;color:var(--mu);font-weight:600;transition:background .25s,color .25s}.vt .seg button.on{background:var(--acs);color:var(--on)}
// .vt .dz{display:flex;flex-direction:column;align-items:center;gap:6px;padding:32px 16px;text-align:center;border:2px dashed var(--bd);border-radius:16px;cursor:pointer;transition:border-color .2s,background .2s}.vt .dz:hover,.vt .dz.drag{border-color:var(--ac);background:var(--acl)}
// .vt .dico{width:48px;height:48px;border-radius:15px;display:grid;place-items:center;background:var(--acl);color:var(--acs)}
// .vt .flist{display:flex;flex-direction:column;gap:8px}.vt .fhead{display:flex;justify-content:space-between;font-size:13px;font-weight:600;color:var(--mu)}
// .vt .frow{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--bd);border-radius:13px;background:var(--solid)}.vt .frow.error{border-color:var(--r)}.vt .fico{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:var(--acl);color:var(--acs);flex:none}
// .vt .finfo{flex:1;min-width:0}.vt .fname{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vt .fsub{font-size:12.5px;color:var(--mu)}.vt .warn{color:var(--as);margin-left:8px;display:inline-flex;align-items:center;gap:3px}.vt .err{color:var(--r)}.vt .okc{color:var(--g)}
// .vt .prog{height:5px;margin-top:6px;border-radius:5px;background:var(--s2);overflow:hidden}.vt .prog span{display:block;height:100%;width:0;border-radius:5px;background:linear-gradient(90deg,var(--ac),var(--acs))}
// .vt .field{display:flex;flex-direction:column;gap:6px}.vt .field label{font-size:13px;font-weight:600;color:var(--mu)}.vt .irow{display:flex;gap:8px}
// .vt .inp{flex:1;min-width:0;padding:11px 13px;border-radius:11px;border:1px solid var(--bd);background:var(--solid);color:var(--tx);font:14px 'JetBrains Mono',monospace;outline:none;transition:border-color .15s,box-shadow .15s}.vt .inp:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--acl)}
// .vt .meter{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.vt .bars{display:flex;gap:4px}.vt .bars span{width:26px;height:5px;border-radius:4px;background:var(--bd);transition:background .25s}
// .vt .bars.s0 .on,.vt .bars.s1 .on{background:var(--r)}.vt .bars.s2 .on{background:var(--a)}.vt .bars.s3 .on,.vt .bars.s4 .on{background:var(--g)}
// .vt .note{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:var(--mu);background:var(--acl);border-radius:12px;padding:11px 13px}.vt .note svg{flex:none;margin-top:2px;color:var(--acs)}
// .vt .hrow{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:16px;max-width:760px;margin-left:auto;margin-right:auto}.vt .hist{max-width:760px;margin:0 auto;overflow:hidden}.vt .hist ul{list-style:none;margin:0;padding:6px}
// .vt .hist li{display:flex;align-items:center;gap:12px;padding:10px;border-radius:12px;transition:background .15s}.vt .hist li:hover{background:var(--s2)}.vt .hn{flex:1;min-width:0;display:flex;flex-direction:column}.vt .hn b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vt .empty{display:flex;flex-direction:column;align-items:center;gap:8px;padding:40px 16px;color:var(--mu);text-align:center}
// .vt .feats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.vt .feat{padding:24px;display:flex;flex-direction:column;gap:10px;transition:border-color .25s,box-shadow .25s}.vt .feat:hover{border-color:var(--g);box-shadow:0 24px 44px -22px var(--g)}
// .vt .foot{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding-top:28px;padding-bottom:36px;border-top:1px solid var(--bd)}
// .vt .mbg{position:fixed;inset:0;z-index:90;display:grid;place-items:center;padding:16px;background:rgba(10,15,22,.5);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}
// .vt .mcard{position:relative;width:100%;max-width:400px;max-height:92vh;overflow:auto;background:var(--solid);border:1px solid var(--bd);border-radius:20px;padding:28px 24px 24px;display:flex;flex-direction:column;gap:10px;text-align:center;box-shadow:0 30px 70px -20px rgba(0,0,0,.45)}.vt .mx{position:absolute;top:10px;right:10px}
// .vt .check{width:64px;height:64px;margin:0 auto;fill:none;stroke:var(--acs);stroke-width:3;stroke-linecap:round;stroke-linejoin:round}.vt .mcirc{stroke-dasharray:151}.vt .mtick{stroke-dasharray:40}.vt .dls{display:grid;gap:8px;max-height:220px;overflow:auto;margin:6px 0}.vt .dls span{overflow:hidden;text-overflow:ellipsis}.vt .mrow,.vt .mcard,.vt .mbg,.vt .swap{transition-property:border-color,background,box-shadow!important}
// .vt .toasts{position:fixed;right:16px;bottom:16px;z-index:100}.vt .toast{padding:12px 16px;background:var(--solid);border:1px solid var(--bd);border-left:4px solid var(--g);border-radius:12px;box-shadow:var(--sh);font-size:14px;max-width:320px}.vt .toast.bad{border-left-color:var(--r)}
// @media(max-width:960px){.vt .hero{grid-template-columns:1fr;padding-top:44px}.vt .feats{grid-template-columns:1fr 1fr}.vt .links{display:none}.vt .navin{justify-content:space-between}}
// @media(max-width:640px){.vt .stats,.vt .feats{grid-template-columns:1fr}.vt .work{padding:16px}.vt .hrow{flex-direction:column;align-items:flex-start}}
// @media(prefers-reduced-motion:reduce){.vt *{transition:none!important;animation:none!important}}
// `;

// /* ───────────────────────── Entry: waits for GSAP, then renders the app ───────────────────────── */
// export default function Vault() {
//   const [ready, setReady] = useState(Boolean(gsap));
//   useEffect(() => {
//     if (gsap) return undefined;
//     let live = true;
//     loadGsap().then(() => live && setReady(true));
//     return () => { live = false; };
//   }, []);
//   return ready ? <VaultApp /> : <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", fontFamily: "system-ui,sans-serif", color: "#5f6b79" }}>Loading…</div>;
// }