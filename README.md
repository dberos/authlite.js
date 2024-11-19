# authlite.js
Lite authentication system for [Next.js](https://nextjs.org/).
**authlite.js** is designed to simplify the authentication process fitting personal project needs, but can be used by anyone who needs a simple layer of abstraction to their application. Currently maintained for `Next.js v15`.

## Versions

* v1.0.6 Removed OAuth providers as it's not the point of the library.

## Usage

### 1. Create ```.env``` with ```JWT_SECRET="..."```

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

There is no CSP or CORS configuration. Consider calling `validateCsrfToken()` at login or other protected actions. Always opt out api from middleware config to avoid synchronization or other issues. For api routes:

#### route.ts

```typescript
import { NextRequest, NextResponse } from "next/server";

export const POST = async (request: NextRequest) => {
    ...
    const headers = new Headers(request.headers);

    const tokenHeader = headers.get('X-Csrf-Token');
    const tokenCookie = headers.get('Cookie');

    // Check if the CSRF tokens match
    if (tokenHeader !== tokenCookie) {
        return NextResponse.json(
            { success: false, message: 'CSRF token mismatch.' },
            { status: 403 }
        );
    }

    // If tokens match, respond with success
    return NextResponse.json({ success: true, message: 'CSRF token validated successfully.' });
};
```

#### protected-server-action.ts

```typescript
"use server";

import { cookies, headers } from "next/headers";

export const protectedAction = async () => {
    ...
    try {

        // Get headers and cookies
        const headersList = await headers();
        const cookieStore = await cookies();

        // Get csrf from cookie
        const tokenCookie = cookieStore.get('csrfToken')?.value;
        // Get csrf from header
        const tokenHeader = headersList.get('X-Csrf-Token');
        if (!tokenCookie || !tokenHeader) throw new Error('Not valid cookie or header');
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

        if (response.ok) 
            {
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
};

```

## OAuth

For [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) , [Google](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow) etc. providers don't forget to call server or client side on callback page `createSession` with your user object and on client side `onLogin`.
