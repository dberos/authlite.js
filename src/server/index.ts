"use server";

import { cookies, headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { createJwt, decodeJwt, verifyJwt } from "../lib/jwt";
import { MiddlewareCallbackType } from "../lib/utils";
import { generateCsrfToken, verifyCsrfToken } from "../lib/csrf-token";

const jwtSecret = process.env.JWT_SECRET as string;
if (!jwtSecret) throw new Error('No JWT_SECRET provided');
const JWT_SECRET = new TextEncoder().encode(jwtSecret);

const csrfSecret = process.env.TOKEN_SECRET as string;
if (!csrfSecret) throw new Error('No TOKEN_SECRET provided');
const TOKEN_SECRET = new TextEncoder().encode(csrfSecret);

export const AuthMiddlewareUtils = async (request: NextRequest, callback?: MiddlewareCallbackType): Promise<NextResponse> => {
    // Refresh the session
    const refreshedResponse = await refreshSession(request);

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
export const refreshSession = async (request: NextRequest): Promise<NextResponse<unknown>> => {
    // Generate a csrf token
    const csrfToken = await generateCsrfToken('1m', TOKEN_SECRET);
    // Generate a response
    const response = NextResponse.next();
    // Set the response header
    response.headers.set('X-Csrf-Token', csrfToken);
    // Set the response cookie
    response.cookies.set('csrfToken', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 24,
        path: '/',
    });

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
};

/**
 * Validates the csrf token found in cookies and header
 * @async
 * @returns Boolean 
 */
export const validateCsrfToken = async (): Promise<boolean> => {
    // Get the cookies
    const cookieStore = await cookies();
    // Get the headers
    const headersList = await headers();

    // Get the values from cookie and header
    const cookieToken = cookieStore.get('csrfToken')?.value;
    const headerToken = headersList.get('X-Csrf-Token');

    // Verify the tokens
    const isValidCookie = cookieToken ? await verifyCsrfToken(cookieToken, TOKEN_SECRET) : false;
    const isValidHeader = headerToken ? await verifyCsrfToken(headerToken, TOKEN_SECRET) : false;

    if (isValidCookie && isValidHeader) {
        return cookieToken === headerToken;
    }

    return false;
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
 * Server action to fetch X-Csrf-Token header
 * @async
 * @returns csrfToken
 */
export const getCsrfToken = async (): Promise<{ csrfToken: string | null }> => {
    const headersList = await headers();
    const csrfToken = headersList.get('X-Csrf-Token');
    if (csrfToken) {
        return { csrfToken }
    }
    return { csrfToken: null };
}

/**
 * Server action to delete current session
 * @async
 */
export const deleteSession = async () => {
    const cookieStore = await cookies();
    cookieStore?.delete('session');
}
