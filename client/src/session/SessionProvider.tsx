import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { AppState } from "react-native";

import { api, type AuthResult, type ServerAddress } from "@/api/client";
import { WolError } from "@/api/errors";

type Status = "loading" | "signedOut" | "signedIn";

interface SessionValue {
  status: Status;
  userName: string | null;
  server: ServerAddress;
  setServer: (server: ServerAddress) => Promise<void>;
  login: (name: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  requestPasswordReset: (email: string) => Promise<void>;
  resetPassword: (email: string, code: string, newPassword: string) => Promise<void>;
  logout: () => Promise<void>;
  logoutAll: () => Promise<void>;
  deleteAccount: (password: string) => Promise<void>;
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>;
  changeName: (newName: string, password: string) => Promise<void>;
}

const KEY_TOKEN = "session_token";
const KEY_USER = "user_name";
const KEY_HOST = "server_host";
const KEY_PORT = "server_port";
// A token whose LOGOUT did not reach the server; revoked on the next chance.
const KEY_PENDING_LOGOUT = "pending_logout";

const extra = Constants.expoConfig?.extra ?? {};
const DEFAULT_SERVER: ServerAddress = {
  host: typeof extra.serverHost === "string" ? extra.serverHost : "",
  port: typeof extra.serverPort === "number" ? extra.serverPort : 8443,
};

const SessionContext = createContext<SessionValue | null>(null);

async function storeSession(token: string, name: string): Promise<void> {
  await SecureStore.setItemAsync(KEY_TOKEN, token);
  await SecureStore.setItemAsync(KEY_USER, name);
}

async function clearSession(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY_TOKEN);
  await SecureStore.deleteItemAsync(KEY_USER);
}

async function flushPendingLogout(): Promise<void> {
  const token = await SecureStore.getItemAsync(KEY_PENDING_LOGOUT);
  if (token === null) return;
  try {
    await api.revokeToken(token);
    await SecureStore.deleteItemAsync(KEY_PENDING_LOGOUT);
  } catch {
    // Still offline; try again next time.
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [userName, setUserName] = useState<string | null>(null);
  const [server, setServerState] = useState<ServerAddress>(DEFAULT_SERVER);

  const signOutLocally = useCallback(async () => {
    api.disconnect();
    await clearSession();
    setUserName(null);
    setStatus("signedOut");
  }, []);

  const signIn = useCallback(async (result: AuthResult) => {
    await storeSession(result.token, result.name);
    setUserName(result.name);
    setStatus("signedIn");
    void flushPendingLogout();
  }, []);

  useEffect(() => {
    api.onSessionInvalid = () => {
      void signOutLocally();
    };
  }, [signOutLocally]);

  useEffect(() => {
    (async () => {
      let stored: (string | null)[];
      try {
        stored = await Promise.all([
          SecureStore.getItemAsync(KEY_TOKEN),
          SecureStore.getItemAsync(KEY_USER),
          SecureStore.getItemAsync(KEY_HOST),
          SecureStore.getItemAsync(KEY_PORT),
        ]);
      } catch {
        // Unreadable storage would otherwise leave the app on the loading screen for good.
        await clearSession().catch(() => {});
        api.configure(DEFAULT_SERVER, null);
        setStatus("signedOut");
        return;
      }
      const [token, name, host, port] = stored;
      const address: ServerAddress = {
        host: host ?? DEFAULT_SERVER.host,
        port: port ? Number(port) : DEFAULT_SERVER.port,
      };
      setServerState(address);
      api.configure(address, token);
      void flushPendingLogout();
      if (token === null) {
        setStatus("signedOut");
        return;
      }
      // Show the panel right away; an offline server surfaces as errors on the screens.
      setUserName(name);
      setStatus("signedIn");
      api.connect().then(setUserName, () => {});
    })();
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "active") void flushPendingLogout();
      if (status !== "signedIn") return;
      if (state === "active") {
        api.connect().then(setUserName, () => {});
      } else if (state === "background") {
        api.disconnect();
      }
    });
    return () => subscription.remove();
  }, [status]);

  const value = useMemo<SessionValue>(
    () => ({
      status,
      userName,
      server,
      async setServer(address) {
        await SecureStore.setItemAsync(KEY_HOST, address.host);
        await SecureStore.setItemAsync(KEY_PORT, String(address.port));
        setServerState(address);
        api.configure(address, null);
      },
      async login(name, password) {
        await signIn(await api.login(name, password));
      },
      async register(name, email, password) {
        await signIn(await api.register(name, email, password));
      },
      async requestPasswordReset(email) {
        await api.requestPasswordReset(email);
      },
      async resetPassword(email, code, newPassword) {
        await signIn(await api.resetPassword(email, code, newPassword));
      },
      async logout() {
        // Sign out locally even when the server cannot be reached, and revoke the token later.
        const token = await SecureStore.getItemAsync(KEY_TOKEN);
        try {
          await api.logout();
        } catch (err) {
          const alreadyGone = err instanceof WolError && (err.code === "invalid_token" || err.code === "unauthenticated");
          if (token !== null && !alreadyGone) await SecureStore.setItemAsync(KEY_PENDING_LOGOUT, token);
        }
        await signOutLocally();
      },
      async logoutAll() {
        await api.logoutAll();
        await signOutLocally();
      },
      async deleteAccount(password) {
        await api.deleteAccount(password);
        await signOutLocally();
      },
      async changePassword(oldPassword, newPassword) {
        const token = await api.changePassword(oldPassword, newPassword);
        await SecureStore.setItemAsync(KEY_TOKEN, token);
      },
      async changeName(newName, password) {
        const name = await api.changeName(newName, password);
        await SecureStore.setItemAsync(KEY_USER, name);
        setUserName(name);
      },
    }),
    [status, userName, server, signIn, signOutLocally],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (value === null) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
