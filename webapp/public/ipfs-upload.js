// xChat IPFS Uploader
// Encrypt & pin files to vault.x1.xyz — wallet-gated, same key derivation as xChat
// Built: 2026-02-25 | Theo (@xxen_bot) for Jack Levin

// ── Constants ────────────────────────────────────────────────────────────────
const IPFS_API       = 'https://vault.x1.xyz/ipfs';
const DERIVATION_MSG = 'IPFS_ENCRYPTION_KEY_V1';  // matches skills/ipfs-encrypted-storage
const MAX_FILE_SIZE  = 50 * 1024 * 1024;           // 50MB cap
const XCHAT_API_BASE = (() => {
  const m = window.location.pathname.match(/^\/([^/]+)/);
  return m ? `/${m[1]}` : '';
})();

// ── Key derivation (wallet-signature → AES-256-GCM key) ─────────────────────
// Mirrors the Python upload.py logic so files are cross-compatible

async function deriveEncryptionKey(walletProvider, walletAddress) {
  // Ask wallet to sign the derivation message (same as vault.x1.xyz/ipfs/crypto.html)
  let sig;
  try {
    const encodedMsg = new TextEncoder().encode(DERIVATION_MSG);
    sig = await walletProvider.signMessage(encodedMsg, 'utf8');
  } catch (e) {
    throw new Error('Wallet signature rejected — cannot derive encryption key');
  }

  // SHA-256(signature bytes) → 256-bit AES key
  const sigBytes = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
  const keyBytes = await crypto.subtle.digest('SHA-256', sigBytes);
  return await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

// ── Encrypt file ─────────────────────────────────────────────────────────────

async function encryptFile(aesKey, fileBytes, filename) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    fileBytes
  );

  // Pack: IV (12) || ciphertext+tag
  const packed = new Uint8Array(12 + ciphertext.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(ciphertext), 12);

  // Wrap in JSON envelope (matches vault.x1.xyz format)
  const envelope = {
    version: 1,
    algorithm: 'AES-256-GCM',
    filename,
    data: btoa(String.fromCharCode(...packed)),
  };

  return new TextEncoder().encode(JSON.stringify(envelope));
}

// ── Upload to IPFS ───────────────────────────────────────────────────────────

async function uploadToIPFS(encryptedBytes, filename, walletAddress) {
  const blob = new Blob([encryptedBytes], { type: 'application/octet-stream' });
  const form = new FormData();
  form.append('file', blob, filename + '.enc');

  const res = await fetch(`${IPFS_API}/api/v0/add`, {
    method: 'POST',
    headers: {
      'X-Pubkey': walletAddress,
      'X-Filename': filename,
    },
    body: form,
  });

  if (!res.ok) {
    const err = await res.text().catch(() => res.statusText);
    throw new Error(`IPFS upload failed: ${err}`);
  }

  const data = await res.json();
  return data.Hash || data.cid || data.CID;
}

// ── Build xChat share message ────────────────────────────────────────────────

function buildShareMessage(filename, cid, sizeBytes) {
  const sizeFmt = sizeBytes > 1024 * 1024
    ? (sizeBytes / 1024 / 1024).toFixed(1) + ' MB'
    : (sizeBytes / 1024).toFixed(1) + ' KB';

  return `📎 *${filename}* (${sizeFmt})\n` +
    `🔐 Encrypted · Wallet-gated\n` +
    `📦 IPFS: \`${cid}\`\n` +
    `🔗 ${IPFS_API}/files/${cid}\n` +
    `_Decrypt at vault.x1.xyz/ipfs/crypto.html_`;
}

// ── Main uploader class ──────────────────────────────────────────────────────

class XChatIPFSUploader {
  constructor({ walletProvider, walletAddress, onProgress, onComplete, onError }) {
    this.walletProvider  = walletProvider;
    this.walletAddress   = walletAddress;
    this.onProgress      = onProgress  || (() => {});
    this.onComplete      = onComplete  || (() => {});
    this.onError         = onError     || console.error;
    this._aesKey         = null;
  }

  // Derive key once per session
  async init() {
    if (this._aesKey) return;
    this.onProgress({ stage: 'signing', pct: 0, msg: 'Sign to unlock file encryption...' });
    this._aesKey = await deriveEncryptionKey(this.walletProvider, this.walletAddress);
    this.onProgress({ stage: 'ready', pct: 0, msg: 'Ready to upload' });
  }

  async upload(file) {
    try {
      // Validate
      if (file.size > MAX_FILE_SIZE) {
        throw new Error(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max 50 MB.`);
      }

      await this.init();

      // Read
      this.onProgress({ stage: 'reading', pct: 10, msg: `Reading ${file.name}...` });
      const fileBytes = new Uint8Array(await file.arrayBuffer());

      // Encrypt
      this.onProgress({ stage: 'encrypting', pct: 30, msg: 'Encrypting...' });
      const encrypted = await encryptFile(this._aesKey, fileBytes, file.name);

      // Upload
      this.onProgress({ stage: 'uploading', pct: 60, msg: 'Uploading to IPFS...' });
      const cid = await uploadToIPFS(encrypted, file.name, this.walletAddress);

      this.onProgress({ stage: 'done', pct: 100, msg: 'Upload complete!' });

      const result = {
        filename: file.name,
        cid,
        size: file.size,
        shareMessage: buildShareMessage(file.name, cid, file.size),
        decryptUrl: `${IPFS_API}/files/${cid}`,
        vaultUrl: `https://vault.x1.xyz/ipfs/crypto.html#${cid}`,
      };

      this.onComplete(result);
      return result;

    } catch (err) {
      this.onError(err);
      throw err;
    }
  }
}

// ── UI Widget ────────────────────────────────────────────────────────────────
// Drop-in button + modal for xchat.html

function createUploaderUI({ walletProvider, walletAddress, onShareMessage }) {

  // ── Styles ──
  const style = document.createElement('style');
  style.textContent = `
    .ipfs-btn {
      background: none;
      border: none;
      cursor: pointer;
      padding: 6px 8px;
      border-radius: 6px;
      color: #9ca3af;
      font-size: 18px;
      transition: color 0.2s, background 0.2s;
      display: flex;
      align-items: center;
    }
    .ipfs-btn:hover { color: #fff; background: #1e293b; }

    .ipfs-modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.7);
      z-index: 9999;
      align-items: center;
      justify-content: center;
    }
    .ipfs-modal-overlay.open { display: flex; }

    .ipfs-modal {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 24px;
      width: 380px;
      max-width: 95vw;
      color: #fff;
      font-family: inherit;
    }
    .ipfs-modal h3 {
      margin: 0 0 4px;
      font-size: 16px;
      font-weight: 600;
    }
    .ipfs-modal p.sub {
      margin: 0 0 20px;
      font-size: 12px;
      color: #64748b;
    }

    .ipfs-drop-zone {
      border: 2px dashed #1e293b;
      border-radius: 8px;
      padding: 32px 16px;
      text-align: center;
      cursor: pointer;
      transition: border-color 0.2s, background 0.2s;
      margin-bottom: 16px;
    }
    .ipfs-drop-zone:hover,
    .ipfs-drop-zone.drag-over {
      border-color: #3b82f6;
      background: #0f1f3d;
    }
    .ipfs-drop-zone .icon { font-size: 32px; margin-bottom: 8px; }
    .ipfs-drop-zone .hint { font-size: 13px; color: #64748b; }
    .ipfs-drop-zone .hint strong { color: #94a3b8; }

    .ipfs-file-input { display: none; }

    .ipfs-progress {
      display: none;
      margin-bottom: 16px;
    }
    .ipfs-progress.active { display: block; }
    .ipfs-progress-bar-bg {
      background: #1e293b;
      border-radius: 4px;
      height: 6px;
      overflow: hidden;
      margin-bottom: 8px;
    }
    .ipfs-progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #3b82f6, #06b6d4);
      border-radius: 4px;
      transition: width 0.3s;
      width: 0%;
    }
    .ipfs-progress-msg { font-size: 12px; color: #64748b; }

    .ipfs-result {
      display: none;
      background: #0d2137;
      border: 1px solid #1e4976;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
    }
    .ipfs-result.active { display: block; }
    .ipfs-result .cid {
      font-family: monospace;
      font-size: 11px;
      color: #60a5fa;
      word-break: break-all;
      margin: 4px 0 8px;
    }
    .ipfs-result .links { display: flex; gap: 8px; flex-wrap: wrap; }
    .ipfs-result a {
      font-size: 11px;
      color: #3b82f6;
      text-decoration: none;
    }
    .ipfs-result a:hover { text-decoration: underline; }

    .ipfs-actions { display: flex; gap: 8px; justify-content: flex-end; }
    .ipfs-btn-cancel {
      background: #1e293b;
      border: none;
      color: #94a3b8;
      border-radius: 6px;
      padding: 8px 16px;
      cursor: pointer;
      font-size: 13px;
    }
    .ipfs-btn-cancel:hover { background: #263548; }
    .ipfs-btn-send {
      background: #3b82f6;
      border: none;
      color: #fff;
      border-radius: 6px;
      padding: 8px 16px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      display: none;
    }
    .ipfs-btn-send.active { display: block; }
    .ipfs-btn-send:hover { background: #2563eb; }

    .ipfs-error {
      display: none;
      background: #2d1010;
      border: 1px solid #7f1d1d;
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 12px;
      color: #fca5a5;
      margin-bottom: 12px;
    }
    .ipfs-error.active { display: block; }
  `;
  document.head.appendChild(style);

  // ── DOM ──
  const btn = document.createElement('button');
  btn.className = 'ipfs-btn';
  btn.title = 'Attach file (encrypted IPFS)';
  btn.innerHTML = '📎';

  const overlay = document.createElement('div');
  overlay.className = 'ipfs-modal-overlay';
  overlay.innerHTML = `
    <div class="ipfs-modal">
      <h3>📎 Attach File</h3>
      <p class="sub">Encrypted with your wallet key · Stored on IPFS</p>

      <div class="ipfs-drop-zone" id="ipfs-drop">
        <div class="icon">🔐</div>
        <div class="hint">Drop a file here or <strong>click to browse</strong></div>
        <input type="file" class="ipfs-file-input" id="ipfs-file-input">
      </div>

      <div class="ipfs-error" id="ipfs-error"></div>

      <div class="ipfs-progress" id="ipfs-progress">
        <div class="ipfs-progress-bar-bg">
          <div class="ipfs-progress-bar" id="ipfs-bar"></div>
        </div>
        <div class="ipfs-progress-msg" id="ipfs-msg">Preparing...</div>
      </div>

      <div class="ipfs-result" id="ipfs-result">
        <div style="font-size:12px;color:#94a3b8;margin-bottom:4px;">✅ Uploaded</div>
        <div class="cid" id="ipfs-cid"></div>
        <div class="links">
          <a id="ipfs-vault-link" href="#" target="_blank">🔓 Decrypt at vault.x1.xyz</a>
          <a id="ipfs-raw-link" href="#" target="_blank">📦 Raw IPFS</a>
        </div>
      </div>

      <div class="ipfs-actions">
        <button class="ipfs-btn-cancel" id="ipfs-cancel">Cancel</button>
        <button class="ipfs-btn-send" id="ipfs-send">Send in Chat ↑</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  // ── Elements ──
  const dropZone    = overlay.querySelector('#ipfs-drop');
  const fileInput   = overlay.querySelector('#ipfs-file-input');
  const errorEl     = overlay.querySelector('#ipfs-error');
  const progressEl  = overlay.querySelector('#ipfs-progress');
  const barEl       = overlay.querySelector('#ipfs-bar');
  const msgEl       = overlay.querySelector('#ipfs-msg');
  const resultEl    = overlay.querySelector('#ipfs-result');
  const cidEl       = overlay.querySelector('#ipfs-cid');
  const vaultLink   = overlay.querySelector('#ipfs-vault-link');
  const rawLink     = overlay.querySelector('#ipfs-raw-link');
  const cancelBtn   = overlay.querySelector('#ipfs-cancel');
  const sendBtn     = overlay.querySelector('#ipfs-send');

  let lastResult = null;

  const uploader = new XChatIPFSUploader({
    walletProvider,
    walletAddress,
    onProgress({ pct, msg }) {
      progressEl.classList.add('active');
      barEl.style.width = pct + '%';
      msgEl.textContent = msg;
    },
    onComplete(result) {
      lastResult = result;
      cidEl.textContent = result.cid;
      vaultLink.href = result.vaultUrl;
      rawLink.href = result.decryptUrl;
      resultEl.classList.add('active');
      sendBtn.classList.add('active');
      progressEl.classList.remove('active');
    },
    onError(err) {
      errorEl.textContent = '⚠️ ' + err.message;
      errorEl.classList.add('active');
      progressEl.classList.remove('active');
    },
  });

  function reset() {
    errorEl.classList.remove('active');
    progressEl.classList.remove('active');
    resultEl.classList.remove('active');
    sendBtn.classList.remove('active');
    barEl.style.width = '0%';
    lastResult = null;
    fileInput.value = '';
  }

  function openModal() { overlay.classList.add('open'); reset(); }
  function closeModal() { overlay.classList.remove('open'); reset(); }

  async function handleFile(file) {
    if (!file) return;
    reset();
    errorEl.classList.remove('active');
    try {
      await uploader.upload(file);
    } catch (_) { /* onError handles it */ }
  }

  // ── Events ──
  btn.addEventListener('click', openModal);
  cancelBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', e => handleFile(e.target.files[0]));

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    handleFile(e.dataTransfer.files[0]);
  });

  sendBtn.addEventListener('click', () => {
    if (lastResult && onShareMessage) {
      onShareMessage(lastResult.shareMessage, lastResult);
    }
    closeModal();
  });

  return { btn, destroy: () => { overlay.remove(); style.remove(); } };
}

// ── Export ────────────────────────────────────────────────────────────────────
export { XChatIPFSUploader, createUploaderUI, buildShareMessage };
