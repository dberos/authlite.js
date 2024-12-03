"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { authenticateSession, deleteSession, getSession } from "../server";
import { AuthContextType } from "../types";

// Create the context for the provider
export const AuthContext = createContext<AuthContextType<any> | undefined>(undefined);

/**
 * Provider to wrap the root layout
 */
export const AuthProvider = <T>({ children }: { children: React.ReactNode }) => {
    const [session, setSession] = useState<T | null | undefined>(null);

    useEffect(() => {
        const findUser = async () => {
            try {
                const { session } = await authenticateSession<T>();
                if (session) {
                    setSession(session);
                }
                else {
                    setSession(null);
                }
            }
            catch (error) {
                console.error(error);
            }
        };
        findUser();
        // Run every minute in case there is no logout but session didn't verify
        // By changing JWT_SECRET
        // The cookie is deleted in middleware
        const intervalId = setInterval(findUser, 60000);
    
        return () => clearInterval(intervalId);
    }, []);

    /**
     * function to call at client login
     * @async
     */
    const onLogin = async (): Promise<void> => {
        try {
            const { session } = await getSession<T>();
            setSession(session);
        }
        catch (error) {
            console.error("Login error:", error);
        }
    };

    /**
     * function to call at client logout
     * @async
     */
    const onLogout = async (): Promise<void> => {
        try {
            await deleteSession();
            setSession(null);
        }
        catch (error) {
            console.error("Logout error:", error);
        }
    };

    // Use React.createElement instead of JSX
    return React.createElement(AuthContext.Provider, { value: { session, setSession, onLogin, onLogout } }, children);
};

/**
 * Hook to access the Provider values at the client
 * @returns session The session object
 * @returns onLogin Utility function to use at login
 * @returns onLogout Utility function to use at logout
 */
export const useAuth = <T = any>(): AuthContextType<T> => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context as AuthContextType<T>;
};

