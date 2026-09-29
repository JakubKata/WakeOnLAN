import * as Clipboard from "expo-clipboard";
import { useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { Text } from "react-native";

import { api, type Claim } from "@/api/client";
import { useAsyncAction } from "@/hooks/useAsyncAction";
import { t } from "@/i18n";
import { Button, Card, ErrorText, Field, FormScreen, Muted, styles } from "@/ui/components";
import { colors } from "@/ui/theme";
import { labelError } from "@/validation";

function formatRemaining(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export default function PairDeviceScreen() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [claim, setClaim] = useState<Claim | null>(null);
  const [now, setNow] = useState(Date.now());
  const [copied, setCopied] = useState(false);
  const { busy, error, setError, run } = useAsyncAction();

  useEffect(() => {
    if (claim === null) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [claim]);

  const create = async () => {
    const problem = labelError(name);
    setError(problem);
    if (problem) return;

    await run(async () => {
      setClaim(await api.createClaim(name.trim()));
      setNow(Date.now());
      setCopied(false);
    });
  };

  const copy = async () => {
    if (claim === null) return;
    await Clipboard.setStringAsync(claim.token);
    setCopied(true);
  };

  if (claim === null) {
    return (
      <FormScreen>
        <Muted>{t.pair.intro}</Muted>
        <Field label={t.pair.name} value={name} onChangeText={setName} placeholder={t.pair.namePlaceholder} autoCapitalize="sentences" />
        <ErrorText>{error}</ErrorText>
        <Button title={t.pair.create} onPress={create} loading={busy} />
      </FormScreen>
    );
  }

  const remaining = claim.expiresAt - now;
  const expired = remaining <= 0;

  return (
    <FormScreen>
      <Text style={styles.title}>{t.pair.tokenFor(name.trim())}</Text>
      <Card style={{ gap: 8 }}>
        <Text selectable style={{ fontFamily: "monospace", fontSize: 16, color: expired ? colors.muted : colors.text }}>
          {claim.token}
        </Text>
        <Muted>{expired ? t.pair.expired : t.pair.validFor(formatRemaining(remaining))}</Muted>
      </Card>
      {expired ? (
        <Button title={t.pair.createAgain} onPress={create} loading={busy} />
      ) : (
        <Button title={copied ? t.pair.copied : t.pair.copy} onPress={copy} />
      )}
      <Card style={{ gap: 6 }}>
        <Text style={styles.title}>{t.pair.nextSteps}</Text>
        <Muted>{t.pair.stepConsole}</Muted>
        <Muted>{t.pair.stepFirmware}</Muted>
        <Muted>{t.pair.stepOnline}</Muted>
      </Card>
      <ErrorText>{error}</ErrorText>
      <Button title={t.common.done} variant="secondary" onPress={() => router.back()} />
    </FormScreen>
  );
}
