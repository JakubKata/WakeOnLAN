import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text } from "react-native";

import { useAsyncAction } from "@/hooks/useAsyncAction";
import { t } from "@/i18n";
import { useSession } from "@/session/SessionProvider";
import { Button, Card, ErrorText, Field, FormScreen, Muted, serverLabel, styles } from "@/ui/components";

export default function LoginScreen() {
  const router = useRouter();
  const { login, server, setServer } = useSession();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, setError, run } = useAsyncAction();

  const [showServer, setShowServer] = useState(!server.host);
  const [host, setHost] = useState(server.host);
  const [port, setPort] = useState(String(server.port));

  /** Saved as soon as it is edited, because the register screen connects to the same server. */
  const saveServer = async (): Promise<boolean> => {
    const portNumber = Number(port);
    if (!host.trim() || !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      setShowServer(true);
      setError(t.login.badServer);
      return false;
    }
    if (host.trim() !== server.host || portNumber !== server.port) {
      await setServer({ host: host.trim(), port: portNumber });
    }
    return true;
  };

  const submit = async () => {
    setError(null);
    if (!(await saveServer())) return;
    if (!name || !password) {
      setError(t.login.missingFields);
      return;
    }
    await run(() => login(name.trim(), password));
  };

  /** The reset screen connects to the saved server, so save any pending edit first. */
  const openReset = async () => {
    setError(null);
    if (await saveServer()) router.push("/reset");
  };

  return (
    <FormScreen>
      <Text style={styles.heading}>Wake on LAN</Text>
      <Field label={t.common.username} value={name} onChangeText={setName} textContentType="username" />
      <Field label={t.common.password} value={password} onChangeText={setPassword} secureTextEntry textContentType="password" />
      <ErrorText>{error}</ErrorText>
      <Button title={t.login.submit} onPress={submit} loading={busy} />
      <Link href="/register" asChild>
        <Pressable>
          <Text style={styles.link}>{t.login.noAccount}</Text>
        </Pressable>
      </Link>
      <Pressable onPress={() => void openReset()}>
        <Text style={styles.link}>{t.login.forgotPassword}</Text>
      </Pressable>

      <Pressable onPress={() => setShowServer((value) => !value)}>
        <Muted>
          {showServer ? "▾" : "▸"} {serverLabel(server)}
        </Muted>
      </Pressable>
      {showServer ? (
        <Card style={{ gap: 12 }}>
          <Field
            label={t.login.serverHost}
            value={host}
            onChangeText={setHost}
            onEndEditing={() => void saveServer()}
            placeholder={t.login.serverHostPlaceholder}
          />
          <Field
            label={t.login.port}
            value={port}
            onChangeText={setPort}
            onEndEditing={() => void saveServer()}
            keyboardType="number-pad"
          />
        </Card>
      ) : null}
    </FormScreen>
  );
}
