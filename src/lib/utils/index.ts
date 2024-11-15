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

export const generateCsrfToken = async (): Promise<string> => {
    // Generate 32 bytes of random data
    const randomValues = crypto.getRandomValues(new Uint8Array(32));
    
    // Convert to hexadecimal string
    return Array.from(randomValues).map(byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * onClick function to login with GitHub
 */
export const loginWithGitHub = (): void => {
    const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID as string;
    const redirectUri = process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI as string;
    const scope = 'user'; 

    const githubAuthURL = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}`;
    
    window.location.href = githubAuthURL;
}

/**
 * onClick function to login with Google
 */
export const loginWithGoogle = ():void => {
    const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID as string;
    const redirectUri = process.env.NEXT_PUBLIC_GOOGLE_REDIRECT_URI as string;
    const scope = 'email profile';
    const state = 'random_state_string';

    const googleAuthURL = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&response_type=code&state=${state}`;

    window.location.href = googleAuthURL;
}