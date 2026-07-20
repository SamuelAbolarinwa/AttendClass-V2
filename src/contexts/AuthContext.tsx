import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";
import { supabase } from "../lib/supabase";

export interface Account {
  id: string;
  full_name: string;
  role: "user" | "manager" | "administrator";
  must_change_password: boolean;
  identifier: string;
  token: string;
}

interface AuthState {
  account: Account | null;
  loading: boolean;
  signIn: (identifier: string, password: string) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
  updateAccount: (updates: Partial<Account>) => void;
}

const STORAGE_KEY = "platform_account";
const AuthContext = createContext<AuthState | undefined>(undefined);

function loadAccount(): Account | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Account) : null;
  } catch {
    return null;
  }
}

function saveAccount(account: Account | null) {
  if (account) {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(account));
  } else {
    sessionStorage.removeItem(STORAGE_KEY);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [account, setAccount] = useState<Account | null>(null);
  const [loading, setLoading] = useState(true);

  // Restore from sessionStorage on mount
  useEffect(() => {
    setAccount(loadAccount());
    setLoading(false);
  }, []);

  const signIn = useCallback(async (identifier: string, password: string) => {
    const { data, error } = await supabase.rpc("platform_login", {
      p_identifier: identifier,
      p_password: password,
    });

    if (error) return { error: error.message };

    const result = data as Record<string, unknown>;
    if (!result.ok) return { error: (result.error as string) || "Login failed" };

    const acct: Account = {
      id: result.id as string,
      full_name: result.full_name as string,
      role: result.role as Account["role"],
      must_change_password: result.must_change_password as boolean,
      identifier: result.identifier as string,
      token: result.token as string,
    };

    setAccount(acct);
    saveAccount(acct);
    return { error: null };
  }, []);

  const signOut = useCallback(async () => {
    if (account?.token) {
      try {
        await supabase.rpc("platform_logout", { p_token: account.token });
      } catch (err) {
        console.error("Sign out RPC Error:", err);
      }
    }
    
    setAccount(null);
    saveAccount(null);
    window.location.href = "/login";
  }, [account]);

  const updateAccount = useCallback((updates: Partial<Account>) => {
    setAccount((prev) => {
      if (!prev) return prev;
      const next = { ...prev, ...updates };
      saveAccount(next);
      return next;
    });
  }, []);

  return (
    <AuthContext.Provider value={{ account, loading, signIn, signOut, updateAccount }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
