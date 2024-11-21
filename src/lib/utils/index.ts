import { NextRequest, NextResponse } from "next/server";
import { AuthMiddlewareUtils } from "../../server";

export type MiddlewareCallbackType = (request: NextRequest) => Promise<void | NextResponse> | void | NextResponse;

/**
 * Middleware utility function
 * @param callback Optional callback handler to protect routes
 * @returns response
 */
export const AuthMiddleware = (callback?: MiddlewareCallbackType) => {
    return (request: NextRequest): Promise<NextResponse> => {
        return AuthMiddlewareUtils(request, callback);
    };
};

/**
 * Utility function to protect routes
 * @async
 * @param request 
 * @param isProtectedRoute Array with the protected routed
 * @param redirectUrl Url to redirect to if user tries to access protected route when not authenticated
 * @throws Error if redirectUrl is a protected route
 * @returns Response
 */
export const protect = async (request: NextRequest, isProtectedRoute: string[], redirectUrl: string, searchParams: boolean = false): Promise<NextResponse | void > => {
    // If trying to access a protected route
    if (isProtectedRoute.some((route) => new RegExp(route).test(request.nextUrl.pathname))) {
        // Prevent endless loop by redirecting to a protected route
        if (isProtectedRoute.some((route) => new RegExp(route).test(redirectUrl))) {
            throw new Error("Redirect URL cannot be a protected route.");
        }
        const url = new URL(redirectUrl, request.url);
        if (searchParams) {
            url.searchParams.set('redirect', request.nextUrl.pathname);
        }
        // Redirect to a non-protected route
        return NextResponse.redirect(url);
    }
};

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