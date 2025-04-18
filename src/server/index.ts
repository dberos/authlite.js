"use server";

import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { createJwt, decodeJwt, verifyJwt } from "../lib/jwt";
import { generateCsrfToken, verifyCsrfToken } from "../lib/csrf-token";
import { Csp, JwtType, Options } from "../types";

const jwtSecret = process.env.JWT_SECRET as string;
if (!jwtSecret) throw new Error('No JWT_SECRET provided');
const JWT_SECRET = new TextEncoder().encode(jwtSecret);

const csrfSecret = process.env.TOKEN_SECRET as string;
if (!csrfSecret) throw new Error('No TOKEN_SECRET provided');
const TOKEN_SECRET = new TextEncoder().encode(csrfSecret);

class MiddlewareResponse {
    // Request and Response
    private response: NextResponse;
    private request: NextRequest;

    // Middleware options
    private options?: Options

    // Resolve promises
    private chain: Promise<void>;

    public constructor(request: NextRequest, options?: Options) {
        this.request = request;
        this.response = NextResponse.next({
            request: {
                headers: this.request.headers
            }
        });

        // Middleware options
        this.options = options;

        // Resolve promises
        this.chain = Promise.resolve();
    }

    public cors(): MiddlewareResponse {
        this.chain = this.chain.then(async () => {
            this.response = await handleCors(this.request, this.response, this.options);
    
            // If the request is preflight or not allowed, throw an error to stop further execution
            if ([204, 403].includes(this.response.status)) {
                throw new Error('Blocked request from CORS');
            }
        })
    
        return this;
    }

    public csp(): MiddlewareResponse {
        // This or any other chain won't execute after blocked CORS request
        // And the code inside won't run
        this.chain = this.chain.then(async () => {
            this.response = await handleCsp(this.request, this.response, this.options);
        });
        // Allow chaining
        return this;
    }

    public session(): MiddlewareResponse {
        this.chain = this.chain.then(async () => {
            this.response = await handleSession(this.request, this.response);
        });
        // Allow chaining
        return this;
    }

    public protect(): MiddlewareResponse {
        const isProtectedRoute = this.options?.isProtectedRoute;
        const redirectUrl = this.options?.redirectUrl;

        if (
            !isProtectedRoute?.length || 
            !redirectUrl ||
            !Array.isArray(isProtectedRoute)
        ) {
            return this;
        }
        this.chain = this.chain.then(async () => {
            if (!this.response.cookies?.get('session')?.value) {
                if (isProtectedRoute.some((route) => new RegExp(route).test(this.request.nextUrl.pathname))) {
                    // Prevent endless loop by redirecting to a protected route
                    if (isProtectedRoute.some((route) => new RegExp(route).test(redirectUrl))) {
                        throw new Error("Redirect URL cannot be a protected route.");
                    }
                    // Create a new URL
                    const url = new URL(redirectUrl, this.request.url);

                    if (this.options?.redirectParam) {
                        url.searchParams.set('redirect', this.request.nextUrl.pathname);
                    }
        
                    // Create a redirect response
                    const redirectResponse = NextResponse.redirect(url);
        
                    // Copy headers from the existing response
                    this.response.headers.forEach((value, key) => {
                        redirectResponse.headers.set(key, value);
                    });
        
                    this.response = redirectResponse;
                }
            }
        })
        // Allow chaining
        return this;
    }

    public async returns(): Promise<NextResponse> {
        try {
            // Await all promises to resolve
            await this.chain;
        } 
        catch {
            // Error thrown from CORS
            return this.response;
        }
        // Return the response
        return this.response;
    }
}

export const AuthMiddlewareUtils = async (
    request: NextRequest,
    options?: Options
): Promise<NextResponse> => {
    // Create a new response and handle all middleware options
    const response = await new MiddlewareResponse(request, options)
    .cors()
    .csp()
    .session()
    .protect()
    .returns();

    return response;
}

/**
 * 
 * @param request NextRequest
 * @param response NextResponse
 * @param options Middleware options
 * @returns NextResponse with correct headers
 */
const handleCors = async (
    request: NextRequest, 
    response: NextResponse,
    options?: Options
): Promise<NextResponse> => {
    // Check for available CORS options
    if (!Array.isArray(options?.allowedOrigins) || options.allowedOrigins.length === 0) {
        return response;
    }
    // CORS options
    const requestHeaders = new Headers(request.headers);
    const origin = requestHeaders.get("origin") ?? "";
    const allowedMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"];
    const allowedHeaders = ["Content-Type", "Authorization", "X-Csrf-Token", "X-Nonce"];

    // Add CORS headers
    const corsHeaders = {
        "Access-Control-Allow-Origin": options.allowedOrigins.join(","),
        "Access-Control-Allow-Methods": allowedMethods.join(","),
        "Access-Control-Allow-Headers": allowedHeaders.join(",")
    };
    Object.entries(corsHeaders).forEach(([key, value]) => response.headers.set(key, value));

    // Handle Preflight Request
    if (request.method === "OPTIONS") {
        // If trying to return .json({}, {...}) it doesn't work
        return new NextResponse(null, { status: 204, headers: corsHeaders });
    }

    // Block CORS requests from unauthorized origins
    if (origin && !options.allowedOrigins.includes(origin)) {
        // If trying to add all previous headers, it doesn't return a 403
        return NextResponse.json(
            { error: "Request blocked from CORS policy" },
            { status: 403, headers: corsHeaders }
        );
    }

    return response;
}

/**
 * 
 * @param request NextRequest
 * @param options Middleware options
 * @returns a generated response with csp headers if provided, for production only
 */
const handleCsp = async (
    request: NextRequest, 
    response: NextResponse,
    options?: Options
): Promise<NextResponse> => {
    if (
        process.env.NODE_ENV === 'development' || 
        options?.csp === undefined || 
        options.csp === Csp.NONE
    ) {
		return response;
	}
    else if (options.csp === Csp.RELAXED) {
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
        
        response.headers.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        return response;
    }
    else {
        // Csp.STRICT
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

        response.headers.set(
            'Content-Security-Policy',
            contentSecurityPolicyHeaderValue
        )
        
        return response;
    }
}

/**
 * @async
 * @param request NextRequest
 * @param response NextResponse
 * @throws Error if jwt signature didn't verify
 * @returns response with jwt cookie if refreshed
 */
const handleSession = async (request: NextRequest, response: NextResponse): Promise<NextResponse> => {
    // Get the session cookie
    const token = request.cookies.get('session')?.value;
    // If no session is available return
    if (!token) {
        response.cookies?.delete('session');
        return response;
    }

    // Decode the token verifying the signature
    const decodedToken = await decodeJwt(token, JWT_SECRET);
    // If signature didn't verify return the response
    if (!decodedToken) {
        // Delete the cookie
        response.cookies?.delete('session');
        return response;
    }
    // Create jwt that lasts 1 minute and cookie 7 days
    const newToken = await createJwt(decodedToken, '1m', JWT_SECRET);

    // Set the new JWT in cookies
    response.cookies.set('session', newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 7,
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
        // Create jwt that lasts 1 minute and cookie 7 days
        const token = await createJwt(user, '1m', JWT_SECRET);
        
        const cookieStore = await cookies();
        cookieStore.set('session', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7,
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
export const getSession = async <T = any>(): Promise<{ session: ( T & JwtType ) | null | undefined }> => {
    const cookieStore = await cookies();
    const token = cookieStore.get('session')?.value;
    if (token) {
        const session = await decodeJwt(token, JWT_SECRET) as ( T & JwtType ) | null | undefined;
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
export const authenticateSession = async <T = any>(): Promise<{ session: ( T & JwtType ) | null | undefined }> => {
    const cookieStore = await cookies();
    const token = cookieStore.get('session')?.value;
    if (token) {
        const session = await verifyJwt(token, JWT_SECRET) as ( T & JwtType ) | null | undefined;
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
export const createCsrfToken = async (): Promise<{ clientToken: string }> => {
    const cookieStore = await cookies();
    const csrfToken = await generateCsrfToken('1m', TOKEN_SECRET);
    cookieStore.set('token', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 30,
        path: '/',
    });
    return { clientToken: csrfToken }
}

/**
 * Server action to fetch csrf token
 * @async
 * @deletes csrf token cookie
 * @returns csrfToken
 */
export const getCsrfToken = async (): Promise<{ serverToken: string | null }> => {
    const cookieStore = await cookies();
    const csrfToken = cookieStore.get('token')?.value;
    cookieStore?.delete('token');
    return csrfToken ? { serverToken: csrfToken } : { serverToken : null };
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
