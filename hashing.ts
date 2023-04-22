export class Hashing {
    /**
     * Generate a salt using crypto.getRandomValues
     * @returns Generated salt
     * @example
     * Hashing.generate_salt().then((salt) => {
     *    // Do something with salt
     * });
     */
    public static async generate_salt(): Promise<string> {
        // Generate salt using crypto.getRandomValues
        return Array.from(crypto.getRandomValues(new Uint32Array(8)), (dec) => {
            return ("0" + dec.toString(36)).substring(-2);
        }).join("");
    }

    /**
     * Generate a hash from a password and salt
     * @param password Password to generate hash from
     * @param salt Salt to generate hash from
     * @returns Generated hash
     * @example
     * Hashing.generate_hash(password, salt).then((hash) => {
     *    // Do something with hash
     * });
     * @example
     * Hashing.generate_hash(password).then((hash) => {
     *   // Do something with hash
     * });
     */
    public static async generate_hash(password: string, salt: string | void) {
        if (!salt) {
            salt = await Hashing.generate_salt();
        }
        let hashArray = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(password + salt)
        );
        let hash = Array.from(new Uint8Array(hashArray), (dec) => {
            return ("0" + dec.toString(36)).substring(-2);
        }).join("");
        return `${hash}.${salt}`;
    }

    /**
     * Verify a password and hash
     * @param password Password to verify
     * @param hash Hash to verify
     * @returns True if password and hash match, false otherwise
     */
    public static async verify_hash(password: string, hash: string) {
        let [_, salt] = hash.split(".");
        return hash === (await Hashing.generate_hash(password, salt));
    }
}
