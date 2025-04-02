export enum Csp {
    STRICT,
    RELAXED,
    NONE
};

export type Options = {
    allowedOrigins?: string[],
    csp?: Csp,
    isProtectedRoute?: string[],
    redirectUrl? : string,
    redirectParam?: boolean
}

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