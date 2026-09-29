import { useRouter } from "expo-router";
import { useEffect, useState } from "react";

import { api } from "@/api/client";
import { useAsyncAction } from "@/hooks/useAsyncAction";
import { useRemote } from "@/hooks/useRemote";
import { t } from "@/i18n";
import { DevicePicker } from "@/ui/DevicePicker";
import { Button, ErrorText, Field, FormScreen, Muted } from "@/ui/components";
import { labelError, normalizeMac } from "@/validation";

const loadDevices = () => api.listDevices();

export default function NewTargetScreen() {
  const router = useRouter();
  const devices = useRemote(loadDevices);
  const [name, setName] = useState("");
  const [mac, setMac] = useState("");
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const { busy, error, setError, run } = useAsyncAction();

  useEffect(() => {
    if (deviceId === null && devices.data?.length === 1) setDeviceId(devices.data[0].id);
  }, [deviceId, devices.data]);

  const submit = async () => {
    const normalized = normalizeMac(mac);
    const problem =
      labelError(name) ?? (normalized ? null : t.validation.mac) ?? (deviceId ? null : t.target.pickDevice);
    setError(problem);
    if (problem || !normalized || !deviceId) return;

    if (await run(() => api.addTarget(deviceId, normalized, name.trim()))) router.back();
  };

  return (
    <FormScreen>
      <Field label={t.common.name} value={name} onChangeText={setName} placeholder={t.target.namePlaceholder} autoCapitalize="sentences" />
      <Field label={t.target.mac} value={mac} onChangeText={setMac} placeholder="AA:BB:CC:DD:EE:FF" autoCapitalize="characters" />
      <Muted>{t.target.macHint}</Muted>
      <ErrorText>{devices.error}</ErrorText>
      {devices.data ? <DevicePicker devices={devices.data} selected={deviceId} onSelect={setDeviceId} /> : null}
      <ErrorText>{error}</ErrorText>
      <Button title={t.target.add} onPress={submit} loading={busy} />
    </FormScreen>
  );
}
