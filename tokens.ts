import { BaseEncryption } from "./encryption";

// ------------ WARNING: The tokens need a private key and expiriy minutes, I recommend using environment variables for these,
// ------------          but i've set them here for ease of testing.

const TOKEN_EXPIRY_MINUTES = 30;

// The token key needs to be a key generated from encryption.ts. This is an example key generated from the string
// "EXAMPLE_TOKEN_KEY_CHANGE_IN_PRODUCTION" and no salt.
const TOKEN_KEY = "16i9Fqqtg2HfYpbKoi3mfbqZ414S0qacqRu/uXW1QAo="; // FIXME: Change this in production

export class Tokens {
    /**
     * Generate a token from a key string and user uuid
     * @param raw_key Key string to generate token from
     * @param user_uuid User uuid to generate token from
     * @returns Generated token
     * @example
     * Tokens.generate_token(raw_key, user_uuid).then((token) => {
     *    // Do something with token
     * });
     */
    public static async generate_token(
        raw_key: string,
        user_uuid: string
    ): Promise<string> {
        // Generate token using key string and user uuid and TOKEN_KEY from env and TOKEN_EXPIRY_MINUTES from env
        const token = await BaseEncryption.encrypt(
            `${user_uuid}.${raw_key}.${
                Date.now() + TOKEN_EXPIRY_MINUTES * 60000
            }`,
            TOKEN_KEY
        );
        return token;
    }

    /**
     * Verify a token
     * @param token Token to verify
     * @returns User uuid and key string if token is valid, false if token is invalid
     * @example
     * Tokens.verify_token(token).then((result) => {
     *   if (result) {
     *    // Do something with result
     *  } else {
     *   // Do something else, token is invalid
     * }
     */
    public static async verify_token(token: string) {
        // Verify token using user uuid and TOKEN_KEY from env
        const raw_token = await BaseEncryption.decrypt(token, TOKEN_KEY);
        // Return false if boolean
        if (typeof raw_token === "boolean") {
            return false;
        }
        const [uuid, key, expiry] = raw_token.split(".");
        if (Date.now() > parseInt(expiry)) {
            return false;
        }
        return [uuid, key];
    }
}
