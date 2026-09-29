import { Stack, useLocalSearchParams, useRouter } from "expo-router";
import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Alert } from "react-native";

import { api } from "@/api/client";
import { WolError, describeError } from "@/api/errors";
import { useAsyncAction } from "@/hooks/useAsyncAction";
import { useRemote } from "@/hooks/useRemote";
import { t } from "@/i18n";
import { DevicePicker } from "@/ui/DevicePicker";
import { Button, Card, ErrorText, Field, FormScreen, Muted } from "@/ui/components";
import { colors } from "@/ui/theme";
import { labelError } from "@/validation";

export default function EditTargetScreen() {
  const router = useRouter();
  const targetId = Number(useLocalSearchParams<{ id: string }>().id);

  const load = useCallback(async () => {
    const [targets, devices] = await Promise.all([api.listTargets(), api.listDevices()]);
    const target = targets.find((item) => item.id === targetId);
    if (!target) throw new WolError("not_found");
    return { target, devices };
  }, [targetId]);
  const { data, error: loadError } = useRemote(load);

  const [name, setName] = useState("");
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const { busy, error, setError, run } = useAsyncAction();

  useEffect(() => {
    if (!data) return;
    setName(data.target.name);
    setDeviceId(data.target.device_id);
  }, [data]);

  if (!data) {
    return (
      <FormScreen>
        {loadError ? <ErrorText>{loadError}</ErrorText> : <ActivityIndicator color={colors.primary} />}
      </FormScreen>
    );
  }

  const { target, devices } = data;

  const save = async () => {
    const problem = labelError(name);
    setError(problem);
    if (problem) return;

    const saved = await run(async () => {
      if (name.trim() !== target.name) await api.renameTarget(target.id, name.trim());
      if (deviceId !== null && deviceId !== target.device_id) await api.assignTarget(target.id, deviceId);
    });
    if (saved) router.back();
  };

  const remove = () => {
    Alert.alert(t.target.removeTitle, t.target.removeMessage(target.name), [
      { text: t.common.cancel, style: "cancel" },
      {
        text: t.common.remove,
        style: "destructive",
        onPress: async () => {
          try {
            await api.removeTarget(target.id);
            router.back();
          } catch (err) {
            Alert.alert(t.common.error, describeError(err));
          }
        },
      },
    ]);
  };

  return (
    <FormScreen>
      <Stack.Screen options={{ title: target.name }} />
      <Field label={t.common.name} value={name} onChangeText={setName} autoCapitalize="sentences" />
      <Card>
        <Muted>{t.target.mac}</Muted>
        <Muted>{target.mac}</Muted>
        <Muted>{t.target.macReadonly}</Muted>
      </Card>
      <DevicePicker devices={devices} selected={deviceId} onSelect={setDeviceId} />
      <ErrorText>{error}</ErrorText>
      <Button title={t.common.save} onPress={save} loading={busy} />
      <Button title={t.target.remove} variant="danger" onPress={remove} disabled={busy} style={{ marginTop: 8 }} />
    </FormScreen>
  );
}
