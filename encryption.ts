export class BaseEncryption {
    /**
     * Convert a CryptoKey to a raw string
     * @param key CryptoKey to convert to raw string
     * @returns Exported key as a raw string
     * @example
     * BaseEncryption.key_to_raw(key).then((raw) => {
     *     // Do something with raw string
     * });
     */
    private static async key_to_raw(key: CryptoKey): Promise<string> {
        return crypto.subtle.exportKey("raw", key).then((keydata) => {
            // Decode to string
            return btoa(
                // @ts-expect-error - Code works, but typescript doesn't like it
                String.fromCharCode(...new Uint8Array(keydata))
            );
        });
    }

    /**
     * Convert a raw string to a CryptoKey
     * @param raw Raw string to convert to CryptoKey
     * @returns CryptoKey
     * @example
     * BaseEncryption.raw_to_key(raw).then((key) => {
     *     // Do something with key
     * });
     */
    private static async raw_to_key(raw: string): Promise<CryptoKey> {
        return crypto.subtle.importKey(
            "raw",
            new Uint8Array(
                atob(raw)
                    .split("")
                    .map((c) => c.charCodeAt(0))
            ),
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Generate a key from a password and salt
     * @param password Password to generate key from
     * @param salt Salt to generate key from
     * @returns Generated key as a raw string
     * @example
     * BaseEncryption.generate_key(password, salt).then((key) => {
     *     // Do something with key
     * });
     */
    public static async generate_key(
        password: string,
        salt: string
    ): Promise<string> {
        return crypto.subtle
            .importKey(
                "raw",
                new TextEncoder().encode(password),
                "PBKDF2",
                false,
                ["deriveKey"]
            )
            .then((passwordKey) => {
                return crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: new TextEncoder().encode(salt),
                        iterations: 100000,
                        hash: "SHA-512",
                    },
                    passwordKey,
                    {
                        name: "AES-GCM",
                        length: 256,
                    },
                    true,
                    ["encrypt", "decrypt"]
                );
            })
            .then((key) => {
                return BaseEncryption.key_to_raw(key);
            });
    }

    /**
     * Encrypt a string using a raw key
     * @param text Text to encrypt
     * @param raw_key Raw key to encrypt with
     * @returns Encrypted text as a base64 string
     * @example
     * BaseEncryption.encrypt(text, key).then((encrypted) => {
     *     // Do something with encrypted string
     * });
     */
    public static async encrypt(
        text: string,
        raw_key: string
    ): Promise<string> {
        // Encrypt using the crypto web api
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await BaseEncryption.raw_to_key(raw_key);
        const encryptedArray = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                key,
                new TextEncoder().encode(text)
            )
        );
        const encrypted = new Uint8Array(
            salt.length + iv.length + encryptedArray.length
        );
        encrypted.set(salt);
        encrypted.set(iv, salt.length);
        encrypted.set(encryptedArray, salt.length + iv.length);
        return btoa(String.fromCharCode(...encrypted));
    }

    /**
     * Decrypt a string using a raw key
     * @param base64 Base64 string to decrypt
     * @param raw_key Raw key to decrypt with
     * @returns Decrypted text as a string
     * @returns false if decryption failed
     * @example
     * BaseEncryption.decrypt(encrypted, key).then((decrypted) => {
     *    if (decrypted) {
     *       // Do something with decrypted string
     *   } else {
     *      // Decryption failed
     *  }
     */
    public static async decrypt(
        base64: string,
        raw_key: string
    ): Promise<string | boolean> {
        // Decrypt using the crypto web api
        const key = await BaseEncryption.raw_to_key(raw_key);
        const encrypted = new Uint8Array(
            atob(base64)
                .split("")
                .map((c) => {
                    return c.charCodeAt(0);
                })
        );
        const iv = encrypted.slice(16, 28);
        const encryptedArray = encrypted.slice(28);
        try {
            return new TextDecoder().decode(
                new Uint8Array(
                    await crypto.subtle.decrypt(
                        {
                            name: "AES-GCM",
                            iv: iv,
                        },
                        key,
                        encryptedArray
                    )
                )
            );
        } catch (error) {
            return false;
        }
    }
}
