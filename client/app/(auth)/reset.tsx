import { useState } from "react";
import { Text } from "react-native";

import { WolError } from "@/api/errors";
import { useAsyncAction } from "@/hooks/useAsyncAction";
import { t } from "@/i18n";
import { useSession } from "@/session/SessionProvider";
import { Button, ErrorText, Field, FormScreen, Muted, serverLabel, styles } from "@/ui/components";
import { emailError, normalizeResetCode, passwordError } from "@/validation";

export default function ResetPasswordScreen() {
  const { requestPasswordReset, resetPassword, server } = useSession();
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, setError, run } = useAsyncAction();

  const sendCode = async () => {
    const problem = emailError(email);
    setError(problem);
    if (problem) return;
    if (await run(() => requestPasswordReset(email.trim()))) setStep("code");
  };

  const submit = async () => {
    const normalized = normalizeResetCode(code);
    const problem =
      (normalized ? null : t.reset.badCode) ??
      passwordError(password) ??
      (password !== repeat ? t.common.passwordsDiffer : null);
    setError(problem);
    if (problem || !normalized) return;
    await run(async () => {
      try {
        await resetPassword(email.trim(), normalized, password);
      } catch (err) {
        // The server answers a wrong, expired or used code with invalid_token.
        if (err instanceof WolError && err.code === "invalid_token") throw new Error(t.reset.invalidCode);
        throw err;
      }
    });
  };

  if (step === "email") {
    return (
      <FormScreen>
        <Text style={styles.heading}>{t.reset.heading}</Text>
        <Muted>{serverLabel(server)}</Muted>
        <Muted>{t.reset.intro}</Muted>
        <Field label={t.common.email} value={email} onChangeText={setEmail} keyboardType="email-address" textContentType="emailAddress" />
        <ErrorText>{error}</ErrorText>
        <Button title={t.reset.sendCode} onPress={sendCode} loading={busy} />
      </FormScreen>
    );
  }

  return (
    <FormScreen>
      <Text style={styles.heading}>{t.reset.newPasswordHeading}</Text>
      <Muted>{t.reset.codeSent(email.trim())}</Muted>
      <Field label={t.reset.codeLabel} value={code} onChangeText={setCode} autoCapitalize="characters" placeholder="7K3QD-9XW2M" />
      <Field label={t.common.newPassword} value={password} onChangeText={setPassword} secureTextEntry textContentType="newPassword" />
      <Field label={t.common.repeatPassword} value={repeat} onChangeText={setRepeat} secureTextEntry textContentType="newPassword" />
      <ErrorText>{error}</ErrorText>
      <Button title={t.reset.submit} onPress={submit} loading={busy} />
      <Button title={t.reset.resend} variant="secondary" onPress={() => setStep("email")} disabled={busy} />
    </FormScreen>
  );
}
