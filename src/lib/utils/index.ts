import { NextRequest, NextResponse } from "next/server";
import { AuthMiddlewareUtils } from "../../server";
import { Options } from "../../types";

/**
 * Middleware utility function
 * @param options Middleware options
 * @returns response
 * @throws Error for invalid options object, redirectUrl being a protected route, invalid jwt signature
 */
export const AuthMiddleware = (options?: Options) => {
    return (request: NextRequest): Promise<NextResponse> => {
        return AuthMiddlewareUtils(request, options);
    };
};

/**
 * Generates a basic device fingerprint
 * 
 * **NOTE:** This function collects potentially sensitive information
 * 
 * GDPR Compliance: Obtain explicit user consent before calling this function
 * @async
 * @returns fingerprint string 
 */
export const generateFingerprint = async (): Promise<string> => {
    try {
        // Create canvas data
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (ctx) {
            ctx.fillStyle = 'red';
            ctx.fillRect(0, 0, 100, 100);
            ctx.fillStyle = 'white';
            ctx.fillText('fingerprint', 10, 50);
        }
        const canvasData = canvas.toDataURL();

        // Collect other data
        const data = {
            screen: {
                width: window.screen.width || 0,
                height: window.screen.height || 0,
                colorDepth: window.screen.colorDepth || 0,
                pixelRatio: window.devicePixelRatio || 0,
                orientation: screen.orientation?.type || 'unknown',
            },
            browser: {
                userAgent: navigator.userAgent || 'unknown',
                language: navigator.language || 'unknown',
                languages: navigator.languages || [],
                cookieEnabled: navigator.cookieEnabled,
                storage: {
                    localStorage: !!window.localStorage,
                    sessionStorage: !!window.sessionStorage,
                    indexedDB: !!window.indexedDB,
                },
            },
            performance: {
                hardwareConcurrency: navigator.hardwareConcurrency || 0,
            },
            timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
            canvas: canvasData,
        };

        // Stringify the data
        const jsonData = JSON.stringify(data);

        // Hash the data
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(jsonData);
        const hashBuffer = await crypto.subtle.digest('SHA-256', encodedData);

        // Convert hash to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        return hashHex;
    } 
    catch (error) {
        console.error('Error generating fingerprint:', error);
        return 'error';
    }
}

export const parseExpiration = (expiresIn: string): number => {
    const match = expiresIn.match(/^(\d+)([hmsd])$/);
    if (!match) throw new Error('Invalid expiration format');

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 60 * 60;
        case 'd': return value * 60 * 60 * 24;
        default: throw new Error('Invalid expiration unit');
    }
};

// Convert a Uint8Array to a hex string
export const uint8ArrayToHex = (arr: Uint8Array): string => {
    return Array.from(arr).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Convert a hex to a Uint8Array
export const hexToUint8Array = (hex: string): Uint8Array => {
    return new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}