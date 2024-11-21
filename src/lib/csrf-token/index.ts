import { hexToUint8Array, parseExpiration, uint8ArrayToHex } from "../utils";

/**
 * Generates a csrf token with a secret
 * @async
 * @param expiresIn expiration time
 * @param secret your token secret
 * @returns csrf token 
 */
export const generateCsrfToken = async (expiresIn: string, secret: Uint8Array): Promise<string> => {
    // Generate random data
    const randomData = crypto.getRandomValues(new Uint8Array(32));

    // Add expiration
    const expiration = Math.floor(Date.now() / 1000) + parseExpiration(expiresIn);

    // Import a cryptographic key
    const key = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const payload = uint8ArrayToHex(randomData) + "." + expiration;

    // Sign the payload
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));

    // Return the token (random data, expiration, and signature)
    return payload + "." + uint8ArrayToHex(new Uint8Array(signature));
};

/**
 * Verifying a csrf token with a secret
 * @async
 * @param token your csrf token
 * @param secret your token secret
 * @returns Boolean if verified
 */
export const verifyCsrfToken = async (token: string, secret: Uint8Array): Promise<boolean> => {
    // Split the token into random data, expiration, and signature
    const [randomHex, expiration, signatureHex] = token.split(".");
    if (!randomHex || !expiration || !signatureHex) {
        return false;
    }

    // Check if the token has expired
    const now = Math.floor(Date.now() / 1000);
    if (parseInt(expiration, 10) < now) {
        return false;
    }

    const payload = randomHex + "." + expiration;

    // Import the cryptographic key
    const key = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
    );

    // Verify the signature
    const isValid = await crypto.subtle.verify(
        "HMAC",
        key,
        hexToUint8Array(signatureHex),
        new TextEncoder().encode(payload)
    );

    return isValid;
};