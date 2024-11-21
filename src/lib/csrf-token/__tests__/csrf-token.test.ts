import { generateCsrfToken, verifyCsrfToken } from "..";

describe('Csrf Token Utility Functions', () => {

    const secret = 'test-secret-key';
    const TOKEN_SECRET = new TextEncoder().encode(secret);

    const expiresIn = '1s';

    test('should create a valid Csrf Token', async () => {
        const token = await generateCsrfToken(expiresIn, TOKEN_SECRET);
        expect(token).toBeDefined();
    });

    test('should verify a valid Csrf Token', async () => {
        const token = await generateCsrfToken(expiresIn, TOKEN_SECRET);
        const verifiedPayload = await verifyCsrfToken(token, TOKEN_SECRET);
        // Check that the token is verified
        expect(verifiedPayload).toEqual(true); 
    });

    test('should not verify an expired Csrf Token', async () => {
        const token = await generateCsrfToken(expiresIn, TOKEN_SECRET);
        await new Promise(resolve => setTimeout(resolve, 2000));

        const verifiedPayload = await verifyCsrfToken(token, TOKEN_SECRET);
        expect(verifiedPayload).toEqual(false);
    });

    test('should not verify an invalid Csrf Token', async () => {
        const invalidToken = 'invalid.token';
        const decodedPayload = await verifyCsrfToken(invalidToken, TOKEN_SECRET);
        expect(decodedPayload).toEqual(false);
    });
});