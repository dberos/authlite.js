# authlite.js
Lite authentication system for [Next.js](https://nextjs.org/).
**authlite.js** is designed to simplify the authentication process fitting personal project needs, but can be used by anyone who needs a simple layer of abstraction to their application. Currently maintained for `Next.js v15`.

## Installation

```bash
npm install authlite
```

## Versions

| Version | Description |
|:-------------:|:--------------:|
| v1.2      |   Basic device fingerprinting     |
| v1.1      |   Security tweaks     |
| v1.0      |   Initial lib     |

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
import { AuthMiddleware, Csp } from 'authlite';

const allowedOrigins = ['http://localhost:3000/'];

export default AuthMiddleware(allowedOrigins, Csp.NONE);

export const config = {
    matcher: [
        '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
    ],
}

```
| Parameters | Options | Description |
|:-------------:|:--------------:|:--------------:|
| allowedOrigins       |   an array of strings with allowed origins     |  CORS configuration         |
| csp       |   Csp.STRICT, Csp.RELAXED, Csp.NONE     |          CSP configuration |

Add any additional allowed origin urls if needed. For csp, see [docs](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy) for the setup. `STRICT` adds nonces, `RELAXED` doesn't and `NONE` doesn't have any policy. Either `STRICT` and `RELAXED` are configured only for production(`npm run build && npm run start`) so always test in production as well. If `STRICT` is selected you have to mark every page as async and have some async operation inside to avoid errors. If using `next/image`, it will produce errors due to width and height being injected, but it doesn't cause any problems.

#### 3.2 Protected routes

```typescript
import { AuthMiddleware, Csp, protect } from 'authlite';

const allowedOrigins = ['http://localhost:3000/'];

const isProtectedRoute = [
    '/profile(.*)',
    '/dashboard(.*)'
];

const redirectUrl = '/login';

export default AuthMiddleware(
    allowedOrigins, 
    Csp.NONE, 
    (request, response) => {
        return protect(
            request, 
            response,
            isProtectedRoute, 
            redirectUrl
        );
    }
);

export const config = {
    matcher: [
        '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
    ],
}
```
This setup protects all routes in /profile and /dashboard. Other useful configurations are:

* To protect all routes except for login and register:

```typescript
const isProtectedRoute = [
    '/((?!login|register)(.*))'
];

const redirectUrl = '/login';
```

* To protect all routes except for all /auth routes:

```typescript
const isProtectedRoute = [
    '^/(?!auth)(.*)'  
];

const redirectUrl = '/auth/login';
```

* To add searchParam `redirect` when you need to redirect the user back to the protected route after login:

```typescript
protect(
    request, 
    response, 
    isProtectedRoute, 
    redirectUrl, 
    true
);
```

A typical `STRICT` csp setup would look like this:
##### page.tsx

```typescript
import { headers } from "next/headers";
import Component from "./component";
import Image from "next/image";

export default async function Home() {
  // Or simply await headers(); if not planning to use nonce
  // On any other protected action to avoid csp errors
  const headersList = await headers();
  const nonce = headersList.get('X-Nonce') || "";
  return (
    <div>
      <p className="red-box bg-green-500 size-20">
        Hello World
      </p>
      <style nonce={nonce}>
        {
          `
          .red-box {
            background-color: red;
          }
          `
        }
      </style>
      {/* Image will produce error in production */}
      <Image 
      src={'./next.svg'}
      alt="next logo"
      width={100}
      height={100}
      />
      <Component nonce={nonce}/>
    </div>
  );
}
```

##### component.tsx

```typescript
"use client";

import Script from "next/script";

export const Component = ({nonce}: { nonce: string }) =>  {
    const handleClick = async () => {
        console.log('Hello World');
    }
    return (
        <div>
            <button onClick={handleClick}>
                click me
            </button>
            <Script nonce={nonce} id="123">
                {`console.log('Hello World!');`}
            </Script>
        </div>
        
    )
}
```

Root layout can be async too.


### 4. Login / Logout

#### 4.1 Server Side

```typescript
"use server";

import { createSession } from 'authlite';
import { UserType } from '...';

export const loginAction = async (...) => {
    ...
    const user: UserType = {...}
    
    const success = await createSession(user);
    return success;
}
```

#### 4.2 Client Side

```typescript
"use client";

import { useAuth } from 'authlite';
import { useRouter } from "next/navigation";
    
    ...
    const { onLogin, onLogout } = useAuth();
    const router = useRouter();

    const handleLogin = async () => {
        ...
        await onLogin();
        ...
        router.push('...');
    };

    const handleLogout = async () => {
        ...
        await onLogout();
        ...
        router.replace('...');
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

##### route.ts

```typescript
import { NextRequest, NextResponse } from "next/server";
import { verifyJwt } from 'authlite';

export const POST = async (request: NextRequest) => {
    ...
    // Your secret
    const jwtSecret = process.env.JWT_SECRET as string;
    const JWT_SECRET = new TextEncoder().encode(jwtSecret);

    // Get headers
    const headers = new Headers(request.headers);
    const jwtHeader = headers.get('Authorization') || "";

    // Get token
    const token = jwtHeader.split(' ')[1];

    // Verify the token
    const verifiedToken = await verifyJwt(token, JWT_SECRET);
    if (verifiedToken) {
        return NextResponse.json({ success: true, message: 'Jwt validated successfully.' });
    }
    
    return NextResponse.json(
        { success: false, message: 'Invalid Jwt.' },
        { status: 403 }
    );
}
```

##### protected-action.ts

```typescript
"use server";

import { getJwt } from "authlite";

export const protectedAction = async () => {
    ...
    try {
        // Get jwt
        const { jwt } = await getJwt();
        if (!jwt) throw new Error('Invalid jwt');

        // Your fetch
        const response = await fetch('[YOUR_FULL_DOMAIN]', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwt}`
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
        console.error('Error validating jwt or making API request:', error);
        return {
            success: false,
            message: 'An unknown error occurred.',
        };
    }
}

```

## Security

Use in production at your own risk. Always call api routes from a server action. If a session cookie is stolen, it will infinitely produce new sessions, unless `JWT_SECRET` has changed. Consider changing `JWT_SECRET` and `TOKEN_SECRET` frequently to invalidate sessions. Consider calling `await generateFingerprint()`**(GDPR)** at login and add it to the user object and validate it at every protected action. Consider having only your domain as `allowedOrigins` in CORS configuration. Consider having `STRICT` CSP policy. Consider including csrf token in hidden form fields for protected actions.

### fingerprint
In the client component's login submit call `await generateFingerprint()` and add it to the user object. At every protected action generate it again, include it in a hidden form field and validate it server side against the session fingerprint. If it's not validated, call `await deleteSession()` and redirect to the login route, maybe with searchParam `redirect` in the url like in middleware as well.

### csrf token validation

#### client-component.tsx

```typescript
import { createCsrfToken } from 'authlite';
import { protectedAction } from '...''
...
const handleSubmit = async () => {
    ...
    const { csrfToken } = await createCsrfToken();
    ...
    await protectedAction(csrfToken);
}
```

#### protected-action.ts

```typescript
"use server";

import { getCsrfToken, validateCsrfToken } from 'authlite';

export const protectedAction = async (clientToken: string) => {
    ...
    try {
        const { csrfToken } = await getCsrfToken();
        // For server action only
        const isValid = await validateCsrfToken(clientToken, csrfToken);
        ...
        // Or for api routes
        // Verify the token exists
        if (!csrfToken) throw new Error('No csrf token found');
        
        // Data for the POST
        const data = {
            csrfToken: clientToken
        }
        // Your fetch
        const response = await fetch('[YOUR_FULL_DOMAIN]', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Csrf-Token': csrfToken
            },
            body: JSON.stringify(data)
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

#### route.ts

```typescript
import { NextRequest, NextResponse } from "next/server";
import { validateCsrfToken } from 'authlite';

export const POST = async (request: NextRequest) => {
    ...
    // Get headers
    const headers = new Headers(request.headers);
    const tokenHeader = headers.get('X-Csrf-Token') || "";

    // Get request body
    const body = await request.json();
    const tokenBody = body.csrfToken;

    // Verify the tokens
    const isValidCsrfToken = await validateCsrfToken(tokenHeader, tokenBody);
    if (isValidCsrfToken) {
        return NextResponse.json({ success: true, message: 'CSRF token validated successfully.' });
    }
    
    return NextResponse.json(
        { success: false, message: 'Invalid Csrf Token' },
        { status: 403 }
    );
}
```

## OAuth

For [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) , [Google](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow) etc. providers don't forget to call server or client side on callback page `await createSession(user)` with your user object and on client side `await onLogin()`.
