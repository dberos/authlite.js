/** @type {import('ts-jest').JestConfigWithTsJest} **/
module.exports = {
    testEnvironment: "node",
    transform: {
        "^.+\\.tsx?$": ["ts-jest", {}],
    },
    testPathIgnorePatterns: ["<rootDir>/dist/"],
    };
    process.env = Object.assign(process.env, {
        JWT_SECRET: 'test-secret-key',
        TOKEN_SECRET: 'test-secret-key'
      });