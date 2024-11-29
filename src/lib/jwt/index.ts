import { parseExpiration } from "../utils";

const base64UrlEncode = (data: string | ArrayBuffer): string => {
    // Convert string to ArrayBuffer if needed
    const arrayBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    // Convert ArrayBuffer to Base64 string
    const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));

    // Replace Base64 characters to Base64Url format
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const base64UrlDecode = (base64Url: string):string => {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return atob(base64);
}

// Function to create a JWT
export const createJwt = async (payload: object, expiresIn: string, secret: Uint8Array):Promise<string> => {
    try {
        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };

        // Add iat and exp to the payload
        const now = Math.floor(Date.now() / 1000);
        const exp = now + parseExpiration(expiresIn);
        const iat = now;

        const fullPayload = {
            ...payload,
            iat,
            exp,
        };

        // Convert secret key to CryptoKey
        const key = await crypto.subtle.importKey(
            'raw',
            secret,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Encode the header and payload
        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));

        const data = `${encodedHeader}.${encodedPayload}`;

        // Sign the data
        const signatureBuffer = await crypto.subtle.sign(
            'HMAC',
            key,
            new TextEncoder().encode(data)
        );

        const signature = base64UrlEncode(signatureBuffer);

        // Return the JWT
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    } 
    catch (error) {
        console.error('Error creating JWT:', error);
        throw new Error('Failed to create JWT');
    }
}

// Function to verify the JWT signature
const verifySignature = async (token: string, secret: Uint8Array): Promise<boolean> => {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return false;

        const [encodedHeader, encodedPayload, signature] = parts;

        // Convert the signature from Base64URL
        const signatureBuffer = Uint8Array.from(
            atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );

        const data = `${encodedHeader}.${encodedPayload}`;

        // Import the key for verification
        const key = await crypto.subtle.importKey(
            'raw',
            secret,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );

        // Verify the signature
        return await crypto.subtle.verify(
            'HMAC',
            key,
            signatureBuffer,
            new TextEncoder().encode(data)
        );
    } 
    catch (error) {
        console.error('Error verifying JWT signature:', error);
        return false;
    }
}

// Function to verify a JWT (signature and expiration)
export const verifyJwt = async (token: string, secret: Uint8Array): Promise<object | null> => {
    try {
        const isValid = await verifySignature(token, secret);

        // If signature is valid, check the payload
        if (isValid) {
            const [, encodedPayload] = token.split('.');
            const payloadJson = base64UrlDecode(encodedPayload);
            const payload = JSON.parse(payloadJson);
            const now = Math.floor(Date.now() / 1000);

            // Check issued at
            if (payload.iat && payload.iat > now) {
                console.error('JWT issued in the future');
                return null;
            }

            // Check expiration
            if (payload.exp && payload.exp > now) {
                return payload;
            }
        }

        return null;
    } 
    catch (error) {
        console.error('Error verifying JWT:', error);
        return null;
    }
}

// Function to decode the JWT and verify without the claims
export const decodeJwt = async (token: string, secret: Uint8Array): Promise<object | null> => {
    try {
        const isValid = await verifySignature(token, secret);

        // If the signature is valid, decode the payload
        if (isValid) {
            const [, encodedPayload] = token.split('.');
            const payloadJson = base64UrlDecode(encodedPayload);
            const payload = JSON.parse(payloadJson);
            return payload;
        }

        return null;
    } 
    catch (error) {
        console.error('Error decoding JWT:', error);
        return null;
    }
}
