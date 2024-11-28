"use server";

import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { createJwt, decodeJwt, verifyJwt } from "../lib/jwt";
import { CspEnum, MiddlewareCallbackType } from "../lib/utils";
import { generateCsrfToken, verifyCsrfToken } from "../lib/csrf-token";

const jwtSecret = process.env.JWT_SECRET as string;
if (!jwtSecret) throw new Error('No JWT_SECRET provided');
const JWT_SECRET = new TextEncoder().encode(jwtSecret);

const csrfSecret = process.env.TOKEN_SECRET as string;
if (!csrfSecret) throw new Error('No TOKEN_SECRET provided');
const TOKEN_SECRET = new TextEncoder().encode(csrfSecret);

const corsOptions = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Csrf-Token, X-Nonce',
};

export const AuthMiddlewareUtils = async (
    request: NextRequest,
    allowedOrigins: string[],
    csp: CspEnum,
     callback?: MiddlewareCallbackType
): Promise<NextResponse> => {
    // Refresh the session
    const refreshedResponse = await refreshSession(request, allowedOrigins, csp);

    // If the session did not refresh
    if (!refreshedResponse.cookies.get('session')) {
        // If a callback is provided, run it with the request
        if (callback) {
            const callbackResult = await callback(request);
            
            // If callback returns a NextResponse and not Error
            if (callbackResult instanceof NextResponse) {
                return callbackResult;
            }
        }
    }
    // Return the refreshed response
    return refreshedResponse;
}

/**
 * Server action to refresh current session if available
 * @async
 * @param request NextRequest
 * @param response NextResponse
 * @returns refreshed response
 * @throws Error if csrf header doesn't match
 */
export const refreshSession = async (
    request: NextRequest,
    allowedOrigins: string[],
    csp: CspEnum
): Promise<NextResponse<unknown>> => {

    // Generate a response with csp headers
    let response = await handleCsp(csp, request);

    // Hanlde cors options
    response = await handleCors(request, response, allowedOrigins);

    // Hanlde jwt refresh
    response = await handleJwt(request, response);
    
    // Return the response
    return response;
};

/**
 * 
 * @param csp The csp type
 * @param request NextRequest
 * @returns a generated response with csp headers if provided, for production only
 */
const handleCsp = async (csp: CspEnum, request: NextRequest): Promise<NextResponse> => {
    if (process.env.NODE_ENV === 'development') {
		return NextResponse.next();
	}
    if (csp === CspEnum.STRICT) {
        const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
        const cspHeader = `
            default-src 'self';
            script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
            style-src 'self' 'nonce-${nonce}';
            img-src 'self' blob: data:;
            font-src 'self';
            object-src 'none';
            base-uri 'self';
            form-action 'self';
            frame-ancestors 'none';
            upgrade-insecure-requests;
        `
        // Replace newline characters and spaces
        const contentSecurityPolicyHeaderValue = cspHeader
            .replace(/\s{2,}/g, ' ')
            .trim()
        
        const requestHeaders = new Headers(request.headers)
        requestHeaders.set('X-Nonce', nonce)
        
        requestHeaders.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        const response = NextResponse.next({
            request: {
            headers: requestHeaders,
            },
        })
        response.headers.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        return response;
    }
    else if (csp === CspEnum.RELAXED) {
        const cspHeader = `
        default-src 'self';
        script-src 'self' 'unsafe-eval' 'unsafe-inline';
        style-src 'self' 'unsafe-inline';
        img-src 'self' blob: data:;
        font-src 'self';
        object-src 'none';
        base-uri 'self';
        form-action 'self';
        frame-ancestors 'none';
        upgrade-insecure-requests;
        `;
        // Replace newline characters and spaces
        const contentSecurityPolicyHeaderValue = cspHeader
            .replace(/\s{2,}/g, ' ')
            .trim()
        
        const requestHeaders = new Headers(request.headers);
        
        requestHeaders.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        const response = NextResponse.next({
            request: {
            headers: requestHeaders,
            },
        })
        response.headers.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        return response;
    }
    else {
        return NextResponse.next();
    }
}

/**
 * 
 * @param request NextRequest
 * @param response NextResponse
 * @param allowedOrigins Array of allowed origins
 * @returns NextResponse with correct headers
 */
const handleCors = async (
    request: NextRequest, 
    response: NextResponse,
    allowedOrigins: string[]
): Promise<NextResponse> => {
    // Check the origin from the request
    const origin = request.headers.get('origin') ?? ''
    const isAllowedOrigin = allowedOrigins.includes(origin)
    
    // Handle preflighted requests
    const isPreflight = request.method === 'OPTIONS'
    
    if (isPreflight) {
        const preflightHeaders = {
        ...(isAllowedOrigin && { 'Access-Control-Allow-Origin': origin }),
        ...corsOptions,
        }
        // Create a new JSON response and copy existing headers
        const jsonResponse = NextResponse.json({}, { headers: preflightHeaders });

        // Copy headers from the original response (if needed)
        response.headers.forEach((value, key) => {
            jsonResponse.headers.set(key, value);
        });

        return jsonResponse;
    }
    
    if (isAllowedOrigin) {
        response.headers.set('Access-Control-Allow-Origin', origin)
    }
    
    Object.entries(corsOptions).forEach(([key, value]) => {
        response.headers.set(key, value)
    })
    
    return response;
}

/**
 * @async
 * @param request NextRequest
 * @param response NextResponse
 * @throws Error if jwt signature didn't verify
 * @returns response with jwt cookie if refreshed
 */
const handleJwt = async (request: NextRequest, response: NextResponse): Promise<NextResponse> => {
    // Get the session cookie
    const token = request.cookies.get('session')?.value;
    // If no session is available return
    if (!token) return response;

    // Decode the token verifying the signature
    const decodedToken = await decodeJwt(token, JWT_SECRET);
    // If signature didn't verify return error
    if (!decodedToken) {
        return NextResponse.json({ error: "Failed to verify JWT signature" }, { status: 403 });
    }
    // Create jwt that lasts 1 minute and cookie 90 days
    const newToken = await createJwt(decodedToken, '1m', JWT_SECRET);

    // Set the new JWT in cookies
    response.cookies.set('session', newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 90,
        path: '/',
    });
    // Return the refreshed response
    return response;
}

/**
 * Utility function to be used at login at the server
 * @async
 * @param user The user object
 * @returns Boolean promise
 */
export const createSession = async (user: object): Promise<boolean> => {
    try {
        const token = await createJwt(user, '1m', JWT_SECRET);
        
        const cookieStore = await cookies();
        // Set the session cookie on the response
        cookieStore.set('session', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 90,
            path: '/',
        });
        return true;
    }
    catch (error) {
        console.error(error);
        return false;
    }
}

/**
 * Server action to fetch current session
 * @async
 * @returns The current session without verifying the jwt claims, only the signature
 * @returns Null if there is no current session or error when decoding the jwt
 */
export const getSession = async <T = any>(): Promise<{ session: T | null | undefined }> => {
    const cookieStore = await cookies();
    const token = cookieStore.get('session')?.value;
    if (token) {
        const session = await decodeJwt(token, JWT_SECRET) as T | null | undefined;
        return { session };
    }
    return { session: null };
}

/**
 * Server action to fetch and authenticate current session
 * @async
 * @returns The current session if authenticated
 * @returns Null if there is no current session or can't verify the jwt
 */
export const authenticateSession = async <T = any>(): Promise<{ session: T | null | undefined }> => {
    const cookieStore = await cookies();
    const token = cookieStore.get('session')?.value;
    if (token) {
        const session = await verifyJwt(token, JWT_SECRET) as T | null | undefined;
        return { session };
    }
    return { session: null };
}

/**
 * Server action to delete current session
 * @async
 */
export const deleteSession = async () => {
    const cookieStore = await cookies();
    cookieStore?.delete('session');
}

/**
 * Server action to fetch the jwt from cookies
 * @async
 * @returns jwt 
 */
export const getJwt = async (): Promise<{ jwt: string | null }> => {
    const cookieStore = await cookies();
    const jwt = cookieStore.get('session')?.value;
    if (jwt) {
        return { jwt };
    }
    return { jwt: null };
}

/**
 * Server action to be called at client to generate and get a csrf token
 * @returns the generated token
 */
export const createCsrfToken = async (): Promise<{ csrfToken: string }> => {
    const cookieStore = await cookies();
    const csrfToken = await generateCsrfToken('1m', TOKEN_SECRET);
    cookieStore.set('token', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 30,
        path: '/',
    });
    return { csrfToken }
}

/**
 * Server action to fetch csrf token
 * @async
 * @deletes csrf token cookie
 * @returns csrfToken
 */
export const getCsrfToken = async (): Promise<{ csrfToken: string | null }> => {
    const cookieStore = await cookies();
    const csrfToken = cookieStore.get('token')?.value;
    cookieStore?.delete('token');
    return csrfToken ? { csrfToken } : { csrfToken : null };
}

/**
 * 
 * @param clientToken the token from the hidden form field
 * @param serverToken the token from calling await getCsrfToken();
 * @returns boolean if they are valid and match
 */
export const validateCsrfToken = async (clientToken: string | null, serverToken: string | null): Promise<boolean> => {
    const isValidClient = await verifyCsrfToken(clientToken ?? "", TOKEN_SECRET);
    const isValidServer = await verifyCsrfToken(serverToken ?? "", TOKEN_SECRET);
    if (isValidClient && isValidServer) {
        return clientToken === serverToken;
    }
    return false;
}
