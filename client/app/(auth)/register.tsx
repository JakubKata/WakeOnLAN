import { useState } from "react";
import { Text } from "react-native";

import { useAsyncAction } from "@/hooks/useAsyncAction";
import { t } from "@/i18n";
import { useSession } from "@/session/SessionProvider";
import { Button, ErrorText, Field, FormScreen, Muted, serverLabel, styles } from "@/ui/components";
import { emailError, passwordError, usernameError } from "@/validation";

export default function RegisterScreen() {
  const { register, server } = useSession();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, setError, run } = useAsyncAction();

  const submit = async () => {
    const problem =
      usernameError(name.trim()) ??
      emailError(email) ??
      passwordError(password) ??
      (password !== repeat ? t.common.passwordsDiffer : null);
    setError(problem);
    if (problem) return;

    await run(() => register(name.trim(), email.trim(), password));
  };

  return (
    <FormScreen>
      <Text style={styles.heading}>{t.register.heading}</Text>
      <Muted>{serverLabel(server)}</Muted>
      <Field label={t.common.username} value={name} onChangeText={setName} textContentType="username" />
      <Field label={t.common.email} value={email} onChangeText={setEmail} keyboardType="email-address" textContentType="emailAddress" />
      <Field label={t.common.password} value={password} onChangeText={setPassword} secureTextEntry textContentType="newPassword" />
      <Field label={t.common.repeatPassword} value={repeat} onChangeText={setRepeat} secureTextEntry textContentType="newPassword" />
      <ErrorText>{error}</ErrorText>
      <Button title={t.register.submit} onPress={submit} loading={busy} />
    </FormScreen>
  );
}
