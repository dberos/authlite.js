import { createJwt, decodeJwt, verifyJwt } from "..";

describe('JWT Utility Functions', () => {

    const secret = 'test-secret-key';
    const JWT_SECRET = new TextEncoder().encode(secret);

    const payload = { userId: 123, username: 'user1', role: 'admin' };
    const expiresIn = '1s';

    test('should create a valid JWT', async () => {
        const token = await createJwt(payload, expiresIn, JWT_SECRET);
        expect(token).toBeDefined();
    });

    test('should verify a valid JWT', async () => {
        const token = await createJwt(payload, expiresIn, JWT_SECRET);
        const verifiedPayload = await verifyJwt(token, JWT_SECRET);
        // Check that the verified payload matches
        expect(verifiedPayload).toEqual(expect.objectContaining(payload)); 
    });

    test('should not verify an expired JWT', async () => {
        const token = await createJwt(payload, expiresIn, JWT_SECRET);
        await new Promise(resolve => setTimeout(resolve, 2000));

        const verifiedPayload = await verifyJwt(token, JWT_SECRET);
        expect(verifiedPayload).toBeNull();
    });

    test('should decode a valid JWT', async () => {
        const token = await createJwt(payload, expiresIn, JWT_SECRET);
        const decodedPayload = await decodeJwt(token, JWT_SECRET);
        // Check that the decoded payload matches
        expect(decodedPayload).toEqual(expect.objectContaining(payload)); 
    });

    test('should not decode an invalid JWT', async () => {
        const invalidToken = 'invalid.token';
        const decodedPayload = await decodeJwt(invalidToken, JWT_SECRET);
        expect(decodedPayload).toBeNull();
    });
});