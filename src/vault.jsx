import React, { useState, useRef, useCallback } from "react";
import { Lock, Eye, EyeOff, Download, ShieldCheck, ShieldAlert } from "lucide-react";

const MAGIC = new TextEncoder().encode("VLT1");
const PBKDF2_ITERATIONS = 250000;

const styles = {
  page: {
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
  },
  card: {
    width: "100%",
    maxWidth: 440,
    background: "#FFFFFF",
    border: "1px solid #E2E6EA",
    borderRadius: 16,
    padding: 32,
    boxShadow: "0 24px 48px -28px rgba(27,34,44,0.18)",
  },
  smallText: { color: "#6B7684", fontSize: 13 },
  darkText: { color: "#1B222C" },
  input: {
    flex: 1,
    background: "#F8F9FA",
    border: "1px solid #E2E6EA",
    color: "#1B222C",
    borderRadius: 9,
    padding: "10px 12px",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 14,
    outline: "none",
  },
  actionButton: {
    width: "100%",
    padding: "12px 0",
    border: "none",
    borderRadius: 10,
    fontSize: 14.5,
    fontWeight: 700,
  },
};

function concatBuffers(parts) {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  parts.forEach((part) => {
    output.set(new Uint8Array(part), offset);
    offset += part.byteLength;
  });
  return output;
}

function createHeader(name, mimeType) {
  const nameBytes = new TextEncoder().encode(name);
  const mimeBytes = new TextEncoder().encode(mimeType || "application/octet-stream");
  const header = new Uint8Array(2 + nameBytes.length + 1 + mimeBytes.length);
  const view = new DataView(header.buffer);
  view.setUint16(0, nameBytes.length, true);
  header.set(nameBytes, 2);
  header[2 + nameBytes.length] = mimeBytes.length;
  header.set(mimeBytes, 3 + nameBytes.length);
  return header;
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

async function encryptFile(file, password, updateStatus) {
  updateStatus("Reading file…");
  const fileBuffer = await file.arrayBuffer();
  const payload = concatBuffers([createHeader(file.name, file.type), new Uint8Array(fileBuffer)]);

  updateStatus("Deriving encryption key…");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  updateStatus("Encrypting…");
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return new Blob([concatBuffers([MAGIC, salt, iv, new Uint8Array(cipher)])], {
    type: "application/octet-stream",
  });
}

async function decryptFile(file, password, updateStatus) {
  updateStatus("Reading file…");
  const buffer = new Uint8Array(await file.arrayBuffer());

  if (new TextDecoder().decode(buffer.slice(0, 4)) !== "VLT1") {
    throw new Error("This doesn't look like a Vault-encrypted file.");
  }

  const salt = buffer.slice(4, 20);
  const iv = buffer.slice(20, 32);
  const ciphertext = buffer.slice(32);

  updateStatus("Deriving decryption key…");
  const key = await deriveKey(password, salt);

  updateStatus("Decrypting…");
  let payload;
  try {
    payload = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  } catch {
    throw new Error("Wrong password, or the file is corrupted.");
  }

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const nameLength = view.getUint16(0, true);
  const fileName = new TextDecoder().decode(payload.slice(2, 2 + nameLength));
  const mimeLength = payload[2 + nameLength];
  const mimeStart = 3 + nameLength;
  const mimeType = new TextDecoder().decode(payload.slice(mimeStart, mimeStart + mimeLength));
  const fileBytes = payload.slice(mimeStart + mimeLength);

  return { blob: new Blob([fileBytes], { type: mimeType }), name: fileName };
}

export default function Vault() {
  const [mode, setMode] = useState("encrypt");
  const [files, setFiles] = useState([]);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState({ text: "", type: "" });
  const [downloadLinks, setDownloadLinks] = useState([]);
  const [busy, setBusy] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);

  const fileInputRef = useRef(null);
  const isEncrypt = mode === "encrypt";
  const canSubmit = files.length > 0 && password && !busy;

  const resetAll = () => {
    setFiles([]);
    setStatus({ text: "", type: "" });
    setDownloadLinks([]);
    setShowSuccessModal(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const switchMode = (nextMode) => {
    setMode(nextMode);
    resetAll();
  };

  const handleFiles = useCallback((incomingFiles) => {
    if (!incomingFiles?.length) return;
    const selected = Array.from(incomingFiles).filter(Boolean);
    if (!selected.length) return;

    setFiles((current) => {
      const seen = new Set(current.map((item) => `${item.name}-${item.size}-${item.lastModified}`));
      const result = [...current];
      selected.forEach((file) => {
        const key = `${file.name}-${file.size}-${file.lastModified}`;
        if (!seen.has(key)) {
          result.push(file);
          seen.add(key);
        }
      });
      return result;
    });

    setStatus({ text: "", type: "" });
    setDownloadLinks([]);
    setShowSuccessModal(false);
  }, []);

  const onDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    if (event.dataTransfer.files?.length) handleFiles(event.dataTransfer.files);
  };

  const runAction = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setStatus({ text: "", type: "" });
    setDownloadLinks([]);
    setShowSuccessModal(false);

    try {
      const result = [];
      for (const file of files) {
        if (isEncrypt) {
          const blob = await encryptFile(file, password, (text) => setStatus({ text, type: "" }));
          result.push({ url: URL.createObjectURL(blob), name: file.name + ".vault" });
        } else {
          const { blob, name } = await decryptFile(file, password, (text) => setStatus({ text, type: "" }));
          result.push({ url: URL.createObjectURL(blob), name });
        }
      }

      setDownloadLinks(result);
      setPassword("");
      setFiles([]);
      setShowSuccessModal(true);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (error) {
      setStatus({ text: error.message || "Something went wrong.", type: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 30, height: 30, borderRadius: 8, background: "#EAF6F0", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Lock size={16} color="#2F9E76" strokeWidth={2.2} />
          </div>
          <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0 }}>Vault</h1>
        </div>

        <div style={{ ...styles.smallText, margin: "4px 0 24px 40px" }}>
          Local, in-browser AES-256 file encryption
        </div>

        <div style={{ display: "flex", background: "#F1F3F5", border: "1px solid #E2E6EA", borderRadius: 10, padding: 4, marginBottom: 20 }}>
          {["encrypt", "decrypt"].map((option) => (
            <button
              key={option}
              onClick={() => switchMode(option)}
              style={{
                flex: 1,
                padding: "9px 0",
                border: "none",
                borderRadius: 7,
                fontSize: 13.5,
                fontWeight: 600,
                cursor: "pointer",
                background: mode === option ? "#2F9E76" : "transparent",
                color: mode === option ? "#FFFFFF" : "#6B7684",
              }}
            >
              {option === "encrypt" ? "Encrypt" : "Decrypt"}
            </button>
          ))}
        </div>

        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{
            border: `1.5px solid ${dragging ? "#2F9E76" : "#D8DCE1"}`,
            background: dragging ? "rgba(47,158,118,0.05)" : "transparent",
            borderRadius: 12,
            padding: "24px 16px",
            textAlign: "center",
            cursor: "pointer",
            marginBottom: 18,
          }}
        >
          <input ref={fileInputRef} type="file" multiple style={{ display: "none" }} onChange={(event) => handleFiles(event.target.files)} />
          <div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13, wordBreak: "break-all" }}>
            {files.length ? `${files.length} file${files.length > 1 ? "s" : ""} selected` : "Drop a file here, or click to browse"}
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
          <button type="button" onClick={() => fileInputRef.current?.click()} style={{ height: 40, border: "1px solid #E2E6EA", background: "#F8F9FA", color: "#6B7684", borderRadius: 9, padding: "0 12px", fontSize: 12.5, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
            Add files
          </button>
          <button type="button" onClick={resetAll} style={{ height: 40, border: "1px solid #E2E6EA", background: "#F8F9FA", color: "#6B7684", borderRadius: 9, padding: "0 12px", fontSize: 12.5, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
            Remove selected files
          </button>
        </div>

        <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "#6B7684", marginBottom: 6 }}>
          Password
        </label>
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter a strong password" autoComplete="off" style={styles.input} />
          <button type="button" onClick={() => setShowPassword((value) => !value)} title={showPassword ? "Hide password" : "Show password"} style={{ width: 42, background: "#F8F9FA", border: "1px solid #E2E6EA", borderRadius: 9, color: "#6B7684", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        <button
          onClick={runAction}
          disabled={!canSubmit}
          style={{
            ...styles.actionButton,
            cursor: canSubmit ? "pointer" : "not-allowed",
            background: !canSubmit ? "#EEF0F2" : isEncrypt ? "#2F9E76" : "#C68A2E",
            color: !canSubmit ? "#9AA3AF" : "#FFFFFF",
          }}
        >
          {busy ? "Working…" : isEncrypt ? "Encrypt File" : "Decrypt File"}
        </button>

        {status.text && (
          <div style={{ marginTop: 14, fontSize: 13, display: "flex", alignItems: "center", gap: 6, color: status.type === "error" ? "#C13F3F" : "#6B7684" }}>
            {status.type === "error" && <ShieldAlert size={14} />}
            {status.type === "success" && <ShieldCheck size={14} />}
            {status.text}
          </div>
        )}

        {showSuccessModal && downloadLinks.length > 0 && (
          <div style={{ position: "fixed", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: 16, background: "rgba(27, 34, 44, 0.35)", zIndex: 50 }} onClick={() => setShowSuccessModal(false)}>
            <div style={{ width: "100%", maxWidth: 360, background: "#FFFFFF", border: "1px solid #E2E6EA", borderRadius: 14, padding: 18, boxShadow: "0 18px 36px -22px rgba(27,34,44,0.28)", position: "relative" }} onClick={(event) => event.stopPropagation()}>
              <button type="button" onClick={() => setShowSuccessModal(false)} style={{ position: "absolute", top: 10, right: 10, border: "none", background: "transparent", color: "#6B7684", cursor: "pointer", fontSize: 18, lineHeight: 1 }} aria-label="Close success dialog">
                ×
              </button>

              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <ShieldCheck size={16} color="#2F9E76" />
                <div style={{ fontSize: 15, fontWeight: 700, color: "#1B222C" }}>
                  {isEncrypt ? "Files encrypted successfully" : "Files decrypted successfully"}
                </div>
              </div>

              <div style={{ fontSize: 13, color: "#6B7684", marginBottom: 14 }}>
                {downloadLinks.length} result file{downloadLinks.length > 1 ? "s" : ""} are ready to download.
              </div>

              <div style={{ display: "grid", gap: 8 }}>
                {downloadLinks.map((item) => (
                  <a key={`${item.name}-${item.url}`} href={item.url} download={item.name} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6, padding: "10px 0", borderRadius: 9, border: "1px solid #2F9E76", color: "#2F9E76", textDecoration: "none", fontSize: 13.5, fontWeight: 600 }}>
                    <Download size={15} />
                    {item.name}
                  </a>
                ))}
              </div>
            </div>
          </div>
        )}

        <div style={{ marginTop: 20, fontSize: 11.5, color: "#9AA3AF", lineHeight: 1.5, borderTop: "1px solid #EEF0F2", paddingTop: 14 }} />
      </div>
    </div>
  );
}