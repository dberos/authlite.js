"use server";

import { cookies, headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { createJwt, decodeJwt, verifyJwt } from "../lib/jwt";
import { generateCsrfToken, MiddlewareCallbackType } from "../lib/utils";

const secret = process.env.JWT_SECRET as string;
if (!secret) throw new Error('No JWT_SECRET provided');
const JWT_SECRET = new TextEncoder().encode(secret);

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
 * @param request NextReques
 * @param response NextResponse
 * @returns refreshed response
 * @throws Error if csrf header doesn't match
 */
export const refreshSession = async (request: NextRequest): Promise<NextResponse<unknown>> => {
    // Generate a csrf token
    const csrfToken = await generateCsrfToken();
    // Generate a response
    const response = NextResponse.next();
    // Set the response header
    response.headers.set('X-Csrf-Token', csrfToken);
    // Set the response cookie
    response.cookies.set('csrfToken', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60,
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
        sameSite: 'strict',
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

    // Check if they match
    return cookieToken === headerToken;
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
            sameSite: 'strict',
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
 * Server action to fetch the jwt
 * @async
 * @returns Jwt 
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
 * Server action to delete current session
 * @async
 */
export const deleteSession = async () => {
    const cookieStore = await cookies();
    cookieStore?.delete('session');
}

/**
 * Fetches OAuth GitHub access token
 * @async
 * @param code OAuth search param code
 * @returns access token
 */
export const getGitHubAccessToken = async (code: string): Promise<{ data: any }> => {
    // Get the environment variables
    const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    // Check if any of the environment variables are missing
    if (!clientId || !clientSecret) {
        throw new Error('Missing GitHub OAuth environment variables: client_id or client_secret');
    }

    // Fetch the access token
    const response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
        },
        body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            code,
        }),
    });

    // Handle possible errors in the response
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`GitHub access token fetch failed: ${errorData.message || 'Unknown error'}`);
    }

    const data = await response.json();

    // Return the data
    return { data };
};

/**
 * Fetches GitHub user
 * @async
 * @param accessToken 
 * @returns GitHub User object
 * @throws Error if fetch fails
 */
export const getGitHubUser = async (accessToken: string): Promise<{ user: any }> => {
    // Fetch the user
    const response = await fetch('https://api.github.com/user', {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    // Check if the response is successful
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`GitHub user fetch failed: ${errorData.message || 'Unknown error'}`);
    }

    const user = await response.json();

    // Return the user data
    return { user };
};

/**
 * Authentication server action with GitHub
 * @async
 * @param code OAuth search param code
 * @returns GitHub user object
 */
export const authenticateWithGitHub = async (code: string | null): Promise<{ user: any }> => {
    // Ensure code is available
    if (!code) {
        return { user: null };
    }
    try {
        // Fetch the access token
        const { data } = await getGitHubAccessToken(code);
        const access_token = data.access_token;
        // Fetch the user with the access token
        const { user } = await getGitHubUser(access_token);
        // Return the user
        return { user };
    } 
    catch (error) {
        console.error("GitHub authentication failed:", error);
        return { user: null };
    }
}

/**
 * Fetches OAuth Google access token
 * @async
 * @param code  OAuth search param code
 * @returns access token
 */
export const getGoogleAccessToken = async (code: string): Promise<{ data: any }> => {
    // Get the environment variables
    const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID as string;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET as string;
    const redirectUri = process.env.NEXT_PUBLIC_GOOGLE_REDIRECT_URI as string;

    // Check if any of the environment variables are missing
    if (!clientId || !clientSecret || !redirectUri) {
        throw new Error('Missing Google OAuth environment variables');
    }

    const tokenUrl = 'https://oauth2.googleapis.com/token';

    // Prepare JSON payload
    const body = {
        code: code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
    };

    // Fetch the access token
    const response = await fetch(tokenUrl, {
        method: 'POST',
        body: JSON.stringify(body),
        headers: {
            'Content-Type': 'application/json',
        },
    });

    // Check if the response is successful
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Google access token fetch failed: ${errorData.error || 'Unknown error'}`);
    }

    const data = await response.json();

    // Return the data
    return { data };
};

/**
 * Fetches Google user
 * @async
 * @param accessToken 
 * @returns Google user object
 * @throws Error if fetch fails
 */
export const getGoogleUser = async (accessToken: string): Promise<{ user: any }> => {
    // Fetch the user
    const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    // Check if the response is successful
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Google user fetch failed: ${errorData.error || 'Unknown error'}`);
    }

    const user = await response.json();

    // Return the user data
    return { user };
};

/**
 * Authentication server action with Google
 * @async
 * @param code OAuth search param code
 * @returns Google user object
 */
export const authenticateWithGoogle = async (code: string | null): Promise<{ user: any }> => {
    if (!code) {
        return { user: null };
    }

    try {
        // Get Google Access Token
        const { data } = await getGoogleAccessToken(code);
        const access_token = data.access_token;

        // Get Google User
        const { user } = await getGoogleUser(access_token);

        // Return user object
        return { user };
    } 
    catch (error) {
        console.error("Google authentication failed:", error);
        return { user: null };
    }
}
