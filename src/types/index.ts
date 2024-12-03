import { NextRequest, NextResponse } from "next/server";

export enum Csp {
    STRICT,
    RELAXED,
    NONE
};

export type MiddlewareCallbackType = (
    request: NextRequest, 
    response: NextResponse
) => Promise<void | NextResponse> | void | NextResponse;

export type JwtType = {
    iat: number,
    exp: number
};

export type AuthContextType<T> = {
    session: ( T & JwtType ) | null | undefined;
    setSession: React.Dispatch<React.SetStateAction<T | null | undefined>>;
    onLogin: () => Promise<void>;
    onLogout: () => Promise<void>;
};