import { NextRequest, NextResponse } from "next/server";

export type MiddlewareCallbackType = (
    request: NextRequest, 
    response: NextResponse
) => Promise<void | NextResponse> | void | NextResponse;

export enum Csp {
    STRICT,
    RELAXED,
    NONE
};

export type JwtType = {
    iat: number,
    exp: number
};