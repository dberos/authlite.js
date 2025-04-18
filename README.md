# authlite.js
Lite authentication system for [Next.js](https://nextjs.org/).
**authlite.js** is designed to simplify the authentication process fitting personal project needs, but can be used by anyone who needs a simple layer of abstraction to their application. Currently maintained for `Next.js v15`.

## Installation

```bash
npm install authlite
```

## Releases

| Version | Description |
|:-------------:|:--------------:|
| v1.4      |   Modify Middleware     |
| v1.3      |   Minor tweaks     |
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

```typescript
import { AuthMiddleware, Csp, Options } from 'authlite';

// Example usage
const options: Options = {
    allowedOrigins: ['http://localhost:3000'],
    csp: Csp.NONE,
    isProtectedRoute: ['/dashboard(.*)'],
    redirectUrl : '/login',
    redirectParam: true
}

export default AuthMiddleware(options);

export const config = {
    matcher: [
        '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
    ],
}


```
| Parameters | Options | Required |
|:-------------:|:--------------:|:--------------:|
| allowedOrigins       |   an array of strings with allowed origins     |   false    |
|   csp       |   Csp.STRICT, Csp.RELAXED, Csp.NONE     | false    |
|   isProtectedRoute |  an array of strings with protected routes   |   false   |   
|   redirectUrl |  the url to redirect to when accessing a protecting route and user is not authenticated   |   false   |
|   redirectParm |  whether redirect searchParam will be added when accessing a protected route and user is not authenticated   |   false   |

Modify the options to fit your app needs. Everything is optional, though recommended. The basic middleware just handles session. Cors will block requests from unauthorized origins and return origin, method and headers Cors headers for preflight requests, if it is configured.  For csp, see [docs](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy) for the setup. `STRICT` adds nonces, `RELAXED` doesn't and `NONE` doesn't have any policy, which is the default. Either `STRICT` and `RELAXED` are configured only for production(`npm run build && npm run start`) so always test in production as well. Add the array of protected routes and a redirect url to block user from accessing authenticated - only resources. Add `true` to redirectParam to have a redirect searchParam back at the redirectUrl.

#### Useful configurations

* To protect all routes except for login and register:

```typescript
const options: Options = {
    ...
    isProtectedRoute: ['/((?!login|register)(.*))'],
    redirectUrl : '/login',
    ...
}
```

* To protect all routes except for all /auth routes:

```typescript
const options: Options = {
    ...
    isProtectedRoute: ['^/(?!auth)(.*)'],
    redirectUrl : '/auth/login',
    ...
}
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
      {/* Image will produce error in production due to inline width and height */}
      { /* It won't cause any problems */ }
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

### 6. Device fingerprint **(GDPR)**

In the client component's login submit call `await generateFingerprint()` and add it to the user object. At every protected action generate it again, include it in a hidden form field and validate it server side against the session fingerprint. If it's not validated, call `await deleteSession()` and redirect to the login route, maybe with searchParam `redirect` in the url like in middleware as well.

### 7. Csrf Token validation

#### client-component.tsx

```typescript
"use client";

import { createCsrfToken } from 'authlite';
import { protectedAction } from '...';
...
const handleSubmit = async () => {
    ...
    const { clientToken } = await createCsrfToken();
    ...
    await protectedAction(clientToken);
}
```

#### protected-action.ts

```typescript
"use server";

export const protectedAction = async (clientToken: string) => {
    try {
        ...
        const { serverToken } = await getCsrfToken();
        const isValid = await validateCsrfToken(clientToken, serverToken);
        ...
    }
    catch (error) {
        console.error('Error validating csrf-token', error);
    }
}
```

### 8. Api routes

You can call the api from the client or from a server action. If server is preferred, you have to add the full domain before `/api`. If planning to use a server accessing function inside a route handler like `createSession()`, manipulate the response cookies, or accessing the cookieStore, api has to be called from the client.

#### 8.1 Login

##### client-component.tsx

```typescript
"use client";

import { useAuth } from 'authlite';

    ...
    const { onLogin } = useAuth();
    const handleSubmit = async (...) => {
        try {
            ...
            // Your fetch
            const response = await fetch('/api/...', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            // Get response
            const result = await response.json();

            ...
            // Update session status if response is ok
            await onLogin();
            ...
        } 
        catch (error) {
            console.error('Error validating jwt or making API request:', error);
        }
    }
```

##### route.ts

```typescript
import { NextResponse } from "next/server";
import { createSession } from 'authlite';
import { UserType } from '...'

export const POST = async () => {
    ...
    const user: UserType = {...}
    const success = await createSession(user);
    if (success) {
        return NextResponse.json(
            { success: true, message: 'Session created successfully.' });
    } 
    
    return NextResponse.json(
        { success: false, message: 'Failed to create session.' },
        { status: 403 }
    );
}
```

#### 8.2 Validate session

##### client-component.tsx

```typescript
"use client";

import { getJwt } from 'authlite';

...
const handleSubmit = async (...) => {
    try {
        ...
        // Get jwt
        const { jwt } = await getJwt();
        if (!jwt) throw new Error('Invalid jwt');

        // Your fetch
        const response = await fetch('/api/...', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwt}`
            },
        });

        // Get response
        const result = await response.json();
        ...
    } 
    catch (error) {
        console.error('Error validating jwt or making API request:', error);
    }
  }
```

#### route.ts

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
        return NextResponse.json(
            { success: true, message: 'Jwt validated successfully.' });
    }
    
    return NextResponse.json(
        { success: false, message: 'Invalid Jwt.' },
        { status: 403 }
    );
}
```

#### 8.3 Validate csrf-token

##### client-component.tsx

```typescript
"use client";

import { createCsrfToken, getCsrfToken } from 'authlite';

    const handleSubmit = async (...) => {
        try {
            ...
            // Create the csrf token
            const { clientToken } = await createCsrfToken();

            // Get the server csrf token
            const { serverToken } = await getCsrfToken();
            
            // Data for the POST
            const data = {
                csrfToken: clientToken
            }
            // Your fetch
            const response = await fetch('/api/...', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Csrf-Token': serverToken || ""
                },
                body: JSON.stringify(data)
            });

            // Get response
            const result = await response.json();
            ...
        }
        catch (error) {
            console.error('Error validating CSRF or making API request:', error);
        }
```

##### route.ts

```typescript
import { NextRequest, NextResponse } from "next/server";
import { validateCsrfToken } from 'authlite';

export const POST = async (request: NextRequest) => {
    // Get headers
    const headers = new Headers(request.headers);
    const serverToken = headers.get('X-Csrf-Token') || "";

    // Get request body
    const body = await request.json();
    const clientToken = body.csrfToken;

    // Verify the tokens
    const isValidCsrfToken = await validateCsrfToken(clientToken, serverToken);
    if (isValidCsrfToken) {
        return NextResponse.json(
            { success: true, message: 'CSRF token validated successfully.' });
    }
    
    return NextResponse.json(
        { success: false, message: 'Invalid Csrf Token' },
        { status: 403 }
    );
}
```


## Security

Use in production at your own risk. If a session cookie is stolen, it will infinitely produce new sessions, unless `JWT_SECRET` has changed. Consider changing `JWT_SECRET` and `TOKEN_SECRET` frequently to invalidate sessions. Consider calling `await generateFingerprint()`**(GDPR)** at login and add it to the user object and validate it at every protected action. Consider having only your domain as `allowedOrigins` in CORS configuration. Consider having `STRICT` CSP policy. Consider including csrf token in hidden form fields for protected actions.


## OAuth

For [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) , [Google](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow) etc. providers don't forget to call server or client side on callback page `await createSession(user)` with your user object and on client side `await onLogin()`.
