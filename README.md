# authlite.js
Simple authentication system for [Next.js](https://nextjs.org/).
`authlite.js` is designed to simplify the authentication process fitting personal project needs, but can be used by anyone. Currently maintained for **Next.js v15**.
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

export const loginFunction = async (...) => {
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

### 6. For GitHub provider:

#### 6.1 Create GitHub OAuth app with ```Authorization callback URL``` ```...auth/github/callback```

#### 6.2 Add to ```.env``` 

```bash
NEXT_PUBLIC_GITHUB_CLIENT_ID="..."
GITHUB_CLIENT_SECRET="..."
NEXT_PUBLIC_GITHUB_REDIRECT_URI="..."
```
#### 6.3 Create ```app/auth/github/callback/page.tsx```

```typescript
'use client';

import { useEffect, use, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { authenticateWithGitHub, createSession, useAuth } from 'authlite';
import { UserType } from '...';

export default function AuthCallbackPage({searchParams}: { searchParams: Promise<{ [key: string]: string | null }> }) {
    const { code } = use(searchParams);
    const router = useRouter();
    const { onLogin } = useAuth();

    // Skip unnecessary dependency that can cause error
    const onLoginRef = useRef(onLogin);

    useEffect(() => {
        const handleAuth = async () => {
            if (!code) {
                router.push('...');
                return;
            }

            const { user } = await authenticateWithGitHub(code);
            if (user) {
                const userObj: UserType = { ... }
                const success = await createSession(userObj);
                if (success) {
                    await onLoginRef.current();
                    router.push('...');
                }
                else {
                    router.push('...');
                }
            }
            else {
                router.push('...');
            }
            
        };
        handleAuth();
    }, [code, router]);

    // Your HTML
    return <h1>Authenticating...</h1>;
}
```

#### 6.4 On your Login Page

```typescript
"use client";
import { loginWithGitHub } from 'authlite';
...
<button onClick={loginWithGitHub}>
    Login with GitHub
</button>
```

### 7. For Google provider:

#### 7.1 Create Google OAuth app with ```Authorized redirect URIs``` ```...auth/google/callback```

#### 7.2 Add to ```.env```

```bash
NEXT_PUBLIC_GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."
NEXT_PUBLIC_GOOGLE_REDIRECT_URI="..."
```

#### 7.3 Create app/auth/google/callback/page.tsx

```typescript
'use client';

import { useEffect, use, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { authenticateWithGoogle, createSession, useAuth } from 'authlite';
import { UserType } from  '...';

export default function AuthCallbackPage({searchParams}: { searchParams: Promise<{ [key: string]: string | null }> }) {
    const { code } = use(searchParams);
    const router = useRouter();
    const { onLogin } = useAuth();

    // Skip unnecessary dependency that can cause error
    const onLoginRef = useRef(onLogin);

    useEffect(() => {
        const handleAuth = async () => {
            if (!code) {
                router.push('...');
                return;
            }

            const { user } = await authenticateWithGoogle(code);
            if (user) {
                const userObj: UserType = { ... }
                const success = await createSession(userObj);
                if (success) {
                    await onLoginRef.current();
                    router.push('...');
                }
                else {
                    router.push('...');
                }
            }
            else {
                router.push('...');
            }
            
        };
        handleAuth();
    }, [code, router]);

    // Your HTML
    return <h1>Authenticating...</h1>;
}
```

#### 7.4 On your Login Page

```typescript
"use client";
import { loginWithGoogle } from 'authlite';
...
<button onClick={loginWithGoogle}>
    Login with Google
</button>
```
