# authlite.js
Lite authentication system for [Next.js](https://nextjs.org/).
**authlite.js** is designed to simplify the authentication process fitting personal project needs, but can be used by anyone who needs a simple layer of abstraction to their application. Currently maintained for `Next.js v15`.

## Installation

```bash
npm install authlite
```

## Versions

* v1.0.8 Added env variable TOKEN_SECRET and modified csrf token generation and validation.
* v1.0.6 Removed OAuth providers as it's not the point of the library.

## Usage

### 1. Create ```.env``` with:
```bash
JWT_SECRET="..."
TOKEN_SECRET="..."
```

### 2. Wrap root layout with AuthProvider

```typescript
import { AuthProvider } from 'authlite';
...
<AuthProvider>
    {children}
</AuthProvider>
```
### 3. Create middleware.ts at the root of your project

#### 3.1 No protected routes

```typescript
import { AuthMiddleware } from 'authlite';

export default AuthMiddleware();

export const config = {
matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
],
}
```
#### 3.2 Protect e.g all routes in /profile and /dashboard with redirect to /login

```typescript
import { AuthMiddleware, protect } from 'authlite';

const isProtectedRoute = [
    '/profile(.*)',
    '/dashboard(.*)'
];

const redirectUrl = '/login';

export default AuthMiddleware((request) => {
    return protect(request, isProtectedRoute, redirectUrl);
});

export const config = {
matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
],
}
```
#### 3.3 Protect all routes except for /login and /register

```typescript
import { AuthMiddleware, protect } from 'authlite';

const isProtectedRoute = [
    '/((?!login|register)(.*))'
];

const redirectUrl = '/login';

export default AuthMiddleware((request) => {
    return protect(request, isProtectedRoute, redirectUrl);
});

export const config = {
matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
],
}
```
#### 3.4 Protect all routes except for all /auth routes

```typescript
import { AuthMiddleware, protect } from 'authlite';

const isProtectedRoute = [
    '^/(?!auth)(.*)'  
];

const redirectUrl = '/auth/login';

export default AuthMiddleware((request) => {
    return protect(request, isProtectedRoute, redirectUrl);
});

export const config = {
matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
],
}
```
#### 3.5 There are situations where you need to redirect the user to the protected route and want to access searchParams

```typescript
import { AuthMiddleware, protect } from 'authlite';

const isProtectedRoute = [
    '/dashboard(.*)'
];

const redirectUrl = '/login';

export default AuthMiddleware((request) => {
    return protect(request, isProtectedRoute, redirectUrl, true);
});

export const config = {
matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
],
}
```

### 4. Login / Logout

#### 4.1 Server Side

```typescript
"use server";

import { createSession } from 'authlite';
import { UserType } from '...';

export const loginAction = async (...) => {
    ...
    // Consider keeping it simple and create more specific actions
    const user: UserType = {...}
    
    const success = await createSession(user);
    return success;
}
```

#### 4.2 Client Side

```typescript
    import { useAuth } from 'authlite';

    ...
    const { onLogin, onLogout } = useAuth();

    const handleLogin = async () => {
        ...
        await onLogin();
        ...
    };

    const handleLogout = async () => {
        ...
        await onLogout();
        ...
    }
```

### 5. Access Session

#### 5.1 Server Side

##### 5.1.1 Authenticate Session

```typescript
"use server";

import { authenticateSession } from 'authlite';
import { UserType } from '...';

export const protectedAction = async () => {
    ...
    const { session } = await authenticateSession<UserType>();
    ...
}
```

##### 5.1.2 Only Access Session

```typescript
"use server";

import { getSession } from 'authlite';
import { UserType } from '...';

export const protectedAction = async () => {
    ...
    const { session } = await getSession<UserType>();
    ...
}
```

#### 5.2 Client Side

```typescript
"use client";
import { useAuth } from 'authlite';
import { UserType } from '...'

...
const { session } = useAuth<UserType>();
...
```

#### 5.3 For Api Routes

##### 5.3.1 Client Side fetch

```typescript
import { getJwt } from 'authlite';

...
const { jwt } = await getJwt();
const response = await fetch(...);
...
```

##### 5.3.2 route.ts

```typescript
import { verifyJwt } from 'authlite'

....
const secret = process.env.JWT_SECRET as string;
const JWT_SECRET = new TextEncoder().encode(secret);

const header = req.headers.get(...);
const token = header.split(' ')[1];

const verifiedToken = await verifyJwt(token, JWT_SECRET);
...
```

## Security

There is no CSP or CORS configuration. Consider calling `await validateCsrfToken()` at login or other protected actions. Always opt out api from middleware config to avoid synchronization or other issues. For api routes:

#### route.ts

```typescript
import { NextRequest, NextResponse } from "next/server";
import { verifyCsrfToken } from 'authlite';

export const POST = async (request: NextRequest) => {
    ...
    // Get headers
    const headers = new Headers(request.headers);

    const tokenCookie = headers.get('Cookie') || "";
    const tokenHeader = headers.get('X-Csrf-Token') || "";

    // Verify the tokens
    const isValidCookie = await verifyCsrfToken(tokenCookie);
    const isValidHeader = await verifyCsrfToken(tokenHeader);

    if (isValidCookie && isValidHeader) {
        if (tokenHeader === tokenCookie) {
            return NextResponse.json({ success: true, message: 'CSRF token validated successfully.' });
        }   
    }
    return NextResponse.json(
        { success: false, message: 'CSRF token mismatch.' },
        { status: 403 }
    );
}
```

#### protected-server-action.ts

```typescript
"use server";

import { cookies, headers } from "next/headers";

export const protectedAction = async () => {
    ...
    try {
        // Get cookies and headers
        const cookieStore = await cookies();
        const headersList = await headers();

        // Get csrf token from cookie
        const tokenCookie = cookieStore.get('csrfToken')?.value;
        // Get csrf token from header
        const tokenHeader = headersList.get('X-Csrf-Token');

        // Verify they exist
        if (!tokenCookie || !tokenHeader) throw new Error('Not valid cookie or header');

        // Your fetch
        const response = await fetch('[YOUR_FULL_DOMAIN]', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Cookie': tokenCookie,
                'X-Csrf-Token': tokenHeader
            },
        });

        // Get response
        const result = await response.json();

        if (response.ok) {
            console.log(result.message);
            return result;
        } 
        else {
            console.error(result.message);
            throw new Error(`API request failed with status ${response.status}`);
        }
    } 
    catch (error) {
        console.error('Error validating CSRF or making API request:', error);
        return {
            success: false,
            message: 'An unknown error occurred.',
        };
    }
}

```

## OAuth

For [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) , [Google](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow) etc. providers don't forget to call server or client side on callback page `await createSession(user)` with your user object and on client side `await onLogin()`.
