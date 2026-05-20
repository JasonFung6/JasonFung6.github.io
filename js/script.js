document.addEventListener('DOMContentLoaded', async () => {
    const envelopeWrapper = document.getElementById('envelopeWrapper');
    const clickHint = document.getElementById('clickHint');
    const guestNamesEl = document.getElementById('guestNames');
    const guestTimeEl = document.getElementById('guestTime');

    // Resolve guest from URL param
    const params = new URLSearchParams(window.location.search);
    const guestId = params.get('id');

    let guestData = null;

    if (guestId) {
        guestData = await decryptGuest(guestId);
    }

    if (guestData) {
        guestNamesEl.textContent = guestData.names;
        guestTimeEl.textContent = guestData.time;
    } else {
        guestNamesEl.textContent = 'Our Valued Guest';
        guestTimeEl.textContent = 'TBC';
    }

    // Open envelope automatically after a short delay
    setTimeout(() => {
        // First open the flap
        envelopeWrapper.classList.add('flap-open');
        // clickHint.classList.add('hidden');

        // Then release the card after flap has opened
        setTimeout(() => {
            envelopeWrapper.classList.add('opened');
        }, 600);

        // Scroll the card into view after animation completes
        setTimeout(() => {
            const card = document.getElementById('card');
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 1800);
    }, 1000);
});

/**
 * Decrypts guest data using the URL key via Web Crypto API.
 * Uses PBKDF2 for key derivation and AES-GCM for decryption.
 */
async function decryptGuest(key) {
    try {
        // Hash the key to find the entry (same as build script)
        const keyHashBuffer = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(key + GUEST_SALT)
        );
        const keyHashArray = Array.from(new Uint8Array(keyHashBuffer));
        const keyHash = keyHashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);

        const entry = GUESTS_ENCRYPTED[keyHash];
        if (!entry) return null;

        // Derive decryption key using PBKDF2
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(key),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new TextEncoder().encode(GUEST_SALT),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        // Decode the encrypted data
        const iv = Uint8Array.from(atob(entry.iv), c => c.charCodeAt(0));
        const data = Uint8Array.from(atob(entry.data), c => c.charCodeAt(0));
        const tag = Uint8Array.from(atob(entry.tag), c => c.charCodeAt(0));

        // Combine data + auth tag (Web Crypto expects them concatenated)
        const combined = new Uint8Array(data.length + tag.length);
        combined.set(data);
        combined.set(tag, data.length);

        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            derivedKey,
            combined
        );

        const plaintext = new TextDecoder().decode(decrypted);
        return JSON.parse(plaintext);
    } catch (e) {
        console.warn('Unable to decrypt guest data.');
        return null;
    }
}
