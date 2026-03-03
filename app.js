const DEFAULT_CHARSET = "QwErTyUiOpAsDfGhJkLzXcVbNm0123456789@#$%^&*-_=+";
const SALT_LENGTH = 8;
const INTEGRITY_LENGTH = 8;

let charset = DEFAULT_CHARSET;
let base = charset.length;

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function hmacSHA256(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message)));
}

async function generateKeystream(key, length, salt = null) {
  if (!key) throw new Error("Key must not be empty");
  const material = salt ? `${key}:${salt}` : key;
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return Array.from({ length }, (_, i) => hex.charCodeAt(i % hex.length));
}

async function generateHMACKey(text, key) {
  const hmac = await hmacSHA256(key, text);
  return Array.from(hmac).slice(0, INTEGRITY_LENGTH).map(b => charset[b % charset.length]).join('');
}

function generateSalt() {
  return Array.from({ length: SALT_LENGTH }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join('');
}

// ── Base encoding ─────────────────────────────────────────────────────────────

function toCustomBase(num) {
  if (num === 0) return charset[0];
  let result = "";
  while (num > 0) { result = charset[num % base] + result; num = Math.floor(num / base); }
  return result;
}

function fromCustomBase(encoded) {
  if (!encoded) throw new Error("Encoded value cannot be empty");
  return Array.from(encoded).reduce((acc, char) => {
    const idx = charset.indexOf(char);
    if (idx === -1) throw new Error(`Invalid character '${char}'`);
    return acc * base + idx;
  }, 0);
}

// ── Binary helpers ────────────────────────────────────────────────────────────

function toBase64(str) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(str)));
}

function fromBase64(str) {
  return new TextDecoder().decode(Uint8Array.from(atob(str), c => c.charCodeAt(0)));
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function getCharset() {
  const custom = document.getElementById("customCharset").value;
  charset = (custom && custom.length >= 10) ? custom : DEFAULT_CHARSET;
  base = charset.length;
}

function setResult(content, state = '') {
  const box = document.getElementById("result");
  box.className = 'result' + (state ? ` ${state}` : '');
  box.innerHTML = content;
}

// ── Encode ────────────────────────────────────────────────────────────────────

async function encodeText() {
  getCharset();
  const text      = document.getElementById("inputText").value;
  const key       = document.getElementById("key").value;
  const useSalt   = document.getElementById("useSalt").checked;
  const useInt    = document.getElementById("useIntegrity").checked;
  const useBin    = document.getElementById("useBinary").checked;

  if (!key)  return setResult("Error: key must not be empty", "is-error");
  if (!text) return setResult("(empty)", "");

  try {
    const results = await Promise.all(
      text.split('\n').filter(Boolean).map(async line => {
        const input = useBin ? toBase64(line) : line;
        const salt  = useSalt ? generateSalt() : null;
        const ks    = await generateKeystream(key, input.length, salt);
        const parts = Array.from(input).map((c, i) => toCustomBase(c.charCodeAt(0) + ks[i] + i * 7));
        let encoded = parts.join('.');
        if (useInt) encoded = 'i' + (await generateHMACKey(input, key)) + '.' + encoded;
        if (salt)   encoded = salt + '.' + encoded;
        return encoded;
      })
    );
    setResult('<span class="result-label">encoded</span>' + results.join('\n').replace(/</g,'&lt;').replace(/>/g,'&gt;'), 'has-content');
  } catch (e) {
    setResult("Error: " + e.message, "is-error");
  }
}

// ── Decode ────────────────────────────────────────────────────────────────────

async function decodeText() {
  getCharset();
  const text   = document.getElementById("inputText").value;
  const key    = document.getElementById("key").value;
  const useBin = document.getElementById("useBinary").checked;

  if (!key)  return setResult("Error: key must not be empty", "is-error");
  if (!text) return setResult("(empty)", "");

  try {
    const results = await Promise.all(
      text.split('\n').filter(Boolean).map(async line => {
        let parts = line.split('.');
        let salt = null, hasInt = false, givenInt = null;

        // Salt is prepended last during encode, so it appears first
        if (/^[0-9a-f]{8}$/.test(parts[0])) {
          salt  = parts[0];
          parts = parts.slice(1);
        }

        // Integrity marker follows salt
        if (parts[0] && parts[0].startsWith('i') && parts[0].length > 1) {
          hasInt   = true;
          givenInt = parts[0].substring(1, 1 + INTEGRITY_LENGTH);
          parts    = parts.slice(1);
        }

        const ks = await generateKeystream(key, parts.length, salt);
        const decoded = parts.map((p, i) => {
          const n = fromCustomBase(p) - ks[i] - i * 7;
          if (n < 0 || n > 1114111) throw new Error(`Bad data at position ${i}`);
          return String.fromCharCode(n);
        }).join('');

        if (hasInt) {
          const expected = (await generateHMACKey(decoded, key)).substring(0, INTEGRITY_LENGTH);
          if (expected !== givenInt) return '[invalid key or corrupted data]';
        }

        return useBin ? fromBase64(decoded) : decoded;
      })
    );
    setResult('<span class="result-label">decoded</span>' + results.join('\n').replace(/</g,'&lt;').replace(/>/g,'&gt;'), 'has-content');
  } catch (e) {
    setResult("Error: " + e.message, "is-error");
  }
}