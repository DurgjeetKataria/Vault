import React, { useState, useRef, useEffect, useCallback } from "react";
import { Lock, Eye, EyeOff, UploadCloud, Download, ShieldCheck, ShieldAlert } from "lucide-react";

/* =============================================================================
   VAULT — AES-256-GCM file encryption/decryption, entirely client-side.

   Everything happens in the browser via the Web Crypto API. The file and
   password are never sent anywhere.

   File format written by this app ("*.vault"):
   [ "VLT1" magic (4 bytes) ][ salt (16 bytes) ][ iv (12 bytes) ][ ciphertext ]

   The ciphertext itself wraps a small header so the original filename and
   MIME type survive the round trip:
   [ nameLength (2 bytes) ][ name ][ mimeLength (1 byte) ][ mime ][ file bytes ]
   ============================================================================= */

const MAGIC = new TextEncoder().encode("VLT1");
const PBKDF2_ITERATIONS = 250000;

function concatBuffers(buffers) {
  const total = buffers.reduce((sum, b) => sum + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of buffers) {
    out.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  }
  return out;
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptFile(file, password, onProgress) {
  onProgress("Reading file…");
  const fileBuffer = await file.arrayBuffer();

  const nameBytes = new TextEncoder().encode(file.name);
  const mimeBytes = new TextEncoder().encode(file.type || "application/octet-stream");
  const header = new Uint8Array(2 + nameBytes.length + 1 + mimeBytes.length);
  new DataView(header.buffer).setUint16(0, nameBytes.length, true);
  header.set(nameBytes, 2);
  header[2 + nameBytes.length] = mimeBytes.length;
  header.set(mimeBytes, 3 + nameBytes.length);

  const payload = concatBuffers([header, fileBuffer]);

  onProgress("Deriving encryption key…");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  onProgress("Encrypting…");
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);

  const finalBuffer = concatBuffers([MAGIC, salt, iv, ciphertext]);
  return new Blob([finalBuffer], { type: "application/octet-stream" });
}

async function decryptFile(file, password, onProgress) {
  onProgress("Reading file…");
  const buffer = new Uint8Array(await file.arrayBuffer());

  const magic = buffer.slice(0, 4);
  if (new TextDecoder().decode(magic) !== "VLT1") {
    throw new Error("This doesn't look like a Vault-encrypted file.");
  }

  const salt = buffer.slice(4, 20);
  const iv = buffer.slice(20, 32);
  const ciphertext = buffer.slice(32);

  onProgress("Deriving decryption key…");
  const key = await deriveKey(password, salt);

  onProgress("Decrypting…");
  let payload;
  try {
    payload = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  } catch {
    throw new Error("Wrong password, or the file is corrupted.");
  }

  const view = new DataView(payload.buffer);
  const nameLen = view.getUint16(0, true);
  const name = new TextDecoder().decode(payload.slice(2, 2 + nameLen));
  const mimeLen = payload[2 + nameLen];
  const mimeStart = 3 + nameLen;
  const mime = new TextDecoder().decode(payload.slice(mimeStart, mimeStart + mimeLen));
  const fileBytes = payload.slice(mimeStart + mimeLen);

  return { blob: new Blob([fileBytes], { type: mime }), name };
}

// Live "key fingerprint": a quick SHA-256 hash of the password alone, purely
// for visual feedback that the derived key changes as you type. This is NOT
// the real encryption key (that also mixes in a random salt per file).
function useFingerprint(password) {
  const [hues, setHues] = useState(new Array(16).fill(null));

  useEffect(() => {
    if (!password) {
      setHues(new Array(16).fill(null));
      return;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));
      if (cancelled) return;
      const arr = new Uint8Array(digest);
      setHues(Array.from(arr.slice(0, 16), (b) => Math.round((b / 255) * 150) + 150));
    }, 120);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [password]);

  return hues;
}

export default function Vault() {
  const [mode, setMode] = useState("encrypt"); // "encrypt" | "decrypt"
  const [files, setFiles] = useState([]);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState({ text: "", type: "" });
  const [download, setDownload] = useState([]);
  const [busy, setBusy] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);

  const fileInputRef = useRef(null);
  const fingerprint = useFingerprint(password);

  const isEncrypt = mode === "encrypt";
  const canSubmit = Boolean(files.length && password && !busy);

  const switchMode = (next) => {
    setMode(next);
    setStatus({ text: "", type: "" });
    setDownload([]);
    setShowSuccessModal(false);
    setFiles([]);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleFiles = useCallback((incomingFiles) => {
    if (!incomingFiles?.length) return;

    const fileList = Array.from(incomingFiles).filter(Boolean);
    if (!fileList.length) return;

    setFiles((prev) => {
      const seen = new Set(prev.map((f) => `${f.name}-${f.size}-${f.lastModified}`));
      const merged = [...prev];
      for (const file of fileList) {
        const key = `${file.name}-${file.size}-${file.lastModified}`;
        if (!seen.has(key)) {
          merged.push(file);
          seen.add(key);
        }
      }
      return merged;
    });
    setStatus({ text: "", type: "" });
    setDownload([]);
    setShowSuccessModal(false);
  }, []);

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files?.length) handleFiles(e.dataTransfer.files);
  };

  const runAction = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setDownload([]);
    setShowSuccessModal(false);

    try {
      const results = [];

      for (const selectedFile of files) {
        if (isEncrypt) {
          const blob = await encryptFile(selectedFile, password, (t) => setStatus({ text: t, type: "" }));
          results.push({ url: URL.createObjectURL(blob), name: selectedFile.name + ".vault" });
        } else {
          const { blob, name } = await decryptFile(selectedFile, password, (t) => setStatus({ text: t, type: "" }));
          results.push({ url: URL.createObjectURL(blob), name });
        }
      }

      setDownload(results);
      setPassword("");
      setFiles([]);
      if (fileInputRef.current) fileInputRef.current.value = "";
      setStatus({ text: "", type: "" });
      setShowSuccessModal(true);
    } catch (err) {
      setStatus({ text: err.message || "Something went wrong.", type: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "32px 16px",
        background:
          "radial-gradient(circle at 12% 0%, rgba(47,158,118,0.06), transparent 45%), radial-gradient(circle at 88% 100%, rgba(198,138,46,0.06), transparent 45%), #F5F7F8",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Roboto, sans-serif",
        color: "#1B222C",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 440,
          background: "#FFFFFF",
          border: "1px solid #E2E6EA",
          borderRadius: 16,
          padding: 32,
          boxShadow: "0 24px 48px -28px rgba(27,34,44,0.18)",
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 30,
              height: 30,
              borderRadius: 8,
              background: "#EAF6F0",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Lock size={16} color="#2F9E76" strokeWidth={2.2} />
          </div>
          <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, letterSpacing: "0.01em" }}>Vault</h1>
        </div>
        <div style={{ color: "#6B7684", fontSize: 13, margin: "4px 0 24px 40px" }}>
          Local, in-browser AES-256 file encryption
        </div>

        {/* Mode toggle */}
        <div
          style={{
            display: "flex",
            background: "#F1F3F5",
            border: "1px solid #E2E6EA",
            borderRadius: 10,
            padding: 4,
            marginBottom: 20,
          }}
        >
          {["encrypt", "decrypt"].map((m) => (
            <button
              key={m}
              onClick={() => switchMode(m)}
              style={{
                flex: 1,
                padding: "9px 0",
                border: "none",
                borderRadius: 7,
                fontSize: 13.5,
                fontWeight: 600,
                cursor: "pointer",
                background: mode === m ? "#2F9E76" : "transparent",
                color: mode === m ? "#FFFFFF" : "#6B7684",
                transition: "background .15s ease, color .15s ease",
              }}
            >
              {m === "encrypt" ? "Encrypt" : "Decrypt"}
            </button>
          ))}
        </div>

        {/* Dropzone */}
        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{
            border: `1.5px dashed ${dragging ? "#2F9E76" : "#D8DCE1"}`,
            background: dragging ? "rgba(47,158,118,0.05)" : "transparent",
            borderRadius: 12,
            padding: "24px 16px",
            textAlign: "center",
            cursor: "pointer",
            marginBottom: 18,
            transition: "border-color .15s ease, background .15s ease",
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            style={{ display: "none" }}
            onChange={(e) => handleFiles(e.target.files)}
          />
          <UploadCloud size={20} color="#9AA3AF" style={{ marginBottom: 6 }} />
          <div
            style={{
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              fontSize: 13,
              wordBreak: "break-all",
            }}
          >
            {files.length
              ? `${files.length} file${files.length > 1 ? "s" : ""} selected`
              : "Drop a file here, or click to browse"}
          </div>
          {files.length > 0 && (
            <div style={{ color: "#6B7684", fontSize: 12, marginTop: 6, maxHeight: 54, overflowY: "auto" }}>
              {files.map((fileItem) => (
                <div key={`${fileItem.name}-${fileItem.size}-${fileItem.lastModified}`} style={{ marginTop: 2 }}>
                  • {fileItem.name}
                </div>
              ))}
            </div>
          )}
          <div style={{ color: "#6B7684", fontSize: 12.5, marginTop: 4 }}>
            {isEncrypt ? "Any file type — stays on this device" : "Select one or more .vault files created by this app"}
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 18 }}>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            style={{
              height: 40,
              border: "1px solid #E2E6EA",
              background: "#F8F9FA",
              color: "#6B7684",
              borderRadius: 9,
              padding: "0 12px",
              fontSize: 12.5,
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              textAlign: "center",
            }}
          >
            Add files
          </button>
          <button
            type="button"
            onClick={() => {
              setFiles([]);
              if (fileInputRef.current) fileInputRef.current.value = "";
              setStatus({ text: "", type: "" });
              setDownload([]);
              setShowSuccessModal(false);
            }}
            style={{
              height: 40,
              border: "1px solid #E2E6EA",
              background: "#F8F9FA",
              color: "#6B7684",
              borderRadius: 9,
              padding: "0 12px",
              fontSize: 12.5,
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              textAlign: "center",
            }}
          >
            Remove selected files
          </button>
        </div>

        {/* Password */}
        <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "#6B7684", marginBottom: 6 }}>
          Password
        </label>
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter a strong password"
            autoComplete="off"
            style={{
              flex: 1,
              background: "#F8F9FA",
              border: "1px solid #E2E6EA",
              color: "#1B222C",
              borderRadius: 9,
              padding: "10px 12px",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              fontSize: 14,
              outline: "none",
            }}
          />
          <button
            type="button"
            onClick={() => setShowPassword((s) => !s)}
            title={showPassword ? "Hide password" : "Show password"}
            style={{
              width: 42,
              background: "#F8F9FA",
              border: "1px solid #E2E6EA",
              borderRadius: 9,
              color: "#6B7684",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        {/* Fingerprint */}
        <div
          style={{
            fontSize: 11,
            color: "#9AA3AF",
            marginBottom: 6,
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          }}
        >
          Key fingerprint (changes with your password)
        </div>
        <div style={{ display: "flex", gap: 4, marginBottom: 20, height: 20 }}>
          {fingerprint.map((hue, i) => (
            <div
              key={i}
              style={{
                flex: 1,
                borderRadius: 3,
                background: hue === null ? "#EEF0F2" : `hsl(${hue}, 55%, 55%)`,
                transition: "background .25s ease",
              }}
            />
          ))}
        </div>

        {/* Action */}
        <button
          onClick={runAction}
          disabled={!canSubmit}
          style={{
            width: "100%",
            padding: "12px 0",
            border: "none",
            borderRadius: 10,
            fontSize: 14.5,
            fontWeight: 700,
            cursor: canSubmit ? "pointer" : "not-allowed",
            background: !canSubmit ? "#EEF0F2" : isEncrypt ? "#2F9E76" : "#C68A2E",
            color: !canSubmit ? "#9AA3AF" : "#FFFFFF",
            transition: "background .15s ease",
          }}
        >
          {busy ? "Working…" : isEncrypt ? "Encrypt File" : "Decrypt File"}
        </button>

        {/* Status */}
        {status.text && (
          <div
            style={{
              marginTop: 14,
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              gap: 6,
              color: status.type === "error" ? "#C13F3F" : status.type === "success" ? "#2F9E76" : "#6B7684",
            }}
          >
            {status.type === "error" && <ShieldAlert size={14} />}
            {status.type === "success" && <ShieldCheck size={14} />}
            {status.text}
          </div>
        )}

        {/* Success popup */}
        {showSuccessModal && download.length > 0 && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: 16,
              background: "rgba(27, 34, 44, 0.35)",
              zIndex: 50,
            }}
            onClick={() => setShowSuccessModal(false)}
          >
            <div
              style={{
                width: "100%",
                maxWidth: 360,
                background: "#FFFFFF",
                border: "1px solid #E2E6EA",
                borderRadius: 14,
                padding: 18,
                boxShadow: "0 18px 36px -22px rgba(27,34,44,0.28)",
                position: "relative",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <button
                type="button"
                onClick={() => setShowSuccessModal(false)}
                style={{
                  position: "absolute",
                  top: 10,
                  right: 10,
                  border: "none",
                  background: "transparent",
                  color: "#6B7684",
                  cursor: "pointer",
                  fontSize: 18,
                  lineHeight: 1,
                }}
                aria-label="Close success dialog"
              >
                ×
              </button>

              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <ShieldCheck size={16} color="#2F9E76" />
                <div style={{ fontSize: 15, fontWeight: 700, color: "#1B222C" }}>
                  {isEncrypt ? "Files encrypted successfully" : "Files decrypted successfully"}
                </div>
              </div>

              <div style={{ fontSize: 13, color: "#6B7684", marginBottom: 14 }}>
                {download.length} result file{download.length > 1 ? "s" : ""} are ready to download.
              </div>

              <div style={{ display: "grid", gap: 8 }}>
                {download.map((item) => (
                  <a
                    key={`${item.name}-${item.url}`}
                    href={item.url}
                    download={item.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: 6,
                      padding: "10px 0",
                      borderRadius: 9,
                      border: "1px solid #2F9E76",
                      color: "#2F9E76",
                      textDecoration: "none",
                      fontSize: 13.5,
                      fontWeight: 600,
                    }}
                  >
                    <Download size={15} />
                    {item.name}
                  </a>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Footnote */}
        <div
          style={{
            marginTop: 20,
            fontSize: 11.5,
            color: "#9AA3AF",
            lineHeight: 1.5,
            borderTop: "1px solid #EEF0F2",
            paddingTop: 14,
          }}
        >
          {/* Encryption runs entirely in your browser using the Web Crypto API (AES-256-GCM, key derived with
          PBKDF2). Your file and password are never uploaded anywhere. If you forget the password, the file
          cannot be recovered. */}
        </div>
      </div>
    </div>
  );
}