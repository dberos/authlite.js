export { createJwt } from './lib/jwt';
export { verifyJwt } from './lib/jwt';
export { decodeJwt } from './lib/jwt';

export { AuthMiddleware } from './lib/utils';
export { protect } from './lib/utils';
export { loginWithGitHub } from './lib/utils';
export { loginWithGoogle } from './lib/utils';

export { validateCsrfToken } from './server';
export { createSession } from './server';
export { getSession } from './server';
export { authenticateSession } from './server';
export { getJwt } from './server';
export { deleteSession } from './server';
export { authenticateWithGitHub } from './server';
export { authenticateWithGoogle } from './server';

export { AuthProvider } from './client';
export { useAuth } from './client';