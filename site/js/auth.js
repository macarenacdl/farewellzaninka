/* Password + decryption (runs in the visitor's browser, no server needed).

   How it works:
   - The photos and messages are stored ENCRYPTED in the "data" folder (AES-256-GCM).
   - The password is turned into the decryption key with PBKDF2 (600,000 rounds,
     which makes every guess slow).
   - A wrong password simply fails to decrypt: there is no password or fingerprint
     stored anywhere in this site.
   - After a correct password, the key is kept for this browser tab only. */

const ZK = (() => {
  const STORE = "zaninka-key";
  const ITER = 600000;

  const toB64 = (u8) => btoa(String.fromCharCode(...u8));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function fetchBytes(path) {
    const r = await fetch(path, { cache: "no-cache" });
    if (!r.ok) throw new Error("missing:" + path);
    return new Uint8Array(await r.arrayBuffer());
  }

  async function aesDecrypt(key, bytes) {           // bytes = iv(12) + ciphertext
    const iv = bytes.slice(0, 12);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, bytes.slice(12));
    return new Uint8Array(plain);
  }

  async function deriveRaw(password, salt) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, base, 256);
    return new Uint8Array(bits);
  }

  const importKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);

  /* manifest.enc layout: [1 byte version][16 bytes salt][12 bytes iv][ciphertext] */
  async function readManifest(bytes, key) {
    const plain = await aesDecrypt(key, bytes.slice(17));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  return {
    /* Try a password. Returns the manifest, or throws (OperationError = wrong password). */
    async unlock(password) {
      const bytes = await fetchBytes("data/manifest.enc");
      const raw = await deriveRaw(password, bytes.slice(1, 17));
      const key = await importKey(raw);
      const manifest = await readManifest(bytes, key);
      try { sessionStorage.setItem(STORE, toB64(raw)); } catch (e) { /* ignore */ }
      return { manifest, key };
    },

    hasSession() {
      try { return !!sessionStorage.getItem(STORE); } catch (e) { return false; }
    },

    /* Re-open with the key kept from the password step. Returns null if not possible. */
    async session() {
      try {
        const raw = fromB64(sessionStorage.getItem(STORE));
        const key = await importKey(raw);
        const manifest = await readManifest(await fetchBytes("data/manifest.enc"), key);
        return { manifest, key };
      } catch (e) {
        try { sessionStorage.removeItem(STORE); } catch (e2) { /* ignore */ }
        return null;
      }
    },

    /* Decrypts one photo and returns a temporary URL usable in <img src> */
    async photoURL(key, name) {
      const plain = await aesDecrypt(key, await fetchBytes("data/" + name));
      return URL.createObjectURL(new Blob([plain], { type: "image/jpeg" }));
    },

    /* For protected pages: quick check first, then full check */
    requireAccess() {
      if (!this.hasSession()) location.replace("index.html");
    },
    async requireSession() {
      const s = await this.session();
      if (!s) location.replace("index.html");
      return s;
    }
  };
})();
