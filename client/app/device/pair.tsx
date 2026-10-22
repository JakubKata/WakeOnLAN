import { CameraView, useCameraPermissions } from "expo-camera";
import { useRouter } from "expo-router";
import { useEffect, useRef, useState } from "react";
import { AppState, Text, View } from "react-native";

import { api } from "@/api/client";
import { describeError, WolError } from "@/api/errors";
import { t } from "@/i18n";
import { parseSetupCode, provisioning, type DeviceInfo, type WifiNetwork } from "@/provisioning/client";
import { Button, Card, ErrorText, Field, FormScreen, Muted, styles } from "@/ui/components";
import { labelError } from "@/validation";

type Stage = "scan" | "connecting" | "network" | "configuring" | "waiting" | "done";

function byteLength(value: string): number {
  return encodeURIComponent(value).replace(/%[A-F\d]{2}/g, "x").length;
}

export default function PairDeviceScreen() {
  const router = useRouter();
  const [permission, requestPermission] = useCameraPermissions();
  const [camera, setCamera] = useState(false);
  const [stage, setStage] = useState<Stage>("scan");
  const [device, setDevice] = useState<DeviceInfo | null>(null);
  const [owned, setOwned] = useState(false);
  const [networks, setNetworks] = useState<WifiNetwork[]>([]);
  const [name, setName] = useState("");
  const [ssid, setSsid] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const attempt = useRef(0);
  const busy = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wake = useRef<(() => void) | null>(null);

  const stop = () => {
    attempt.current += 1;
    busy.current = false;
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
    wake.current?.();
    wake.current = null;
    void provisioning.cancel();
  };

  useEffect(() => {
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "background") {
        stop();
        setPassword("");
        setCamera(false);
        setStage("scan");
      }
    });
    return () => { subscription.remove(); stop(); };
  }, []);

  const startCamera = async () => {
    setError(null);
    const current = attempt.current;
    const result = permission?.granted ? permission : await requestPermission();
    if (current !== attempt.current) return;
    if (result.granted) setCamera(true);
    else setError(t.pair.cameraPermission);
  };

  const connect = async (raw: string) => {
    if (busy.current) return;
    busy.current = true;
    const current = ++attempt.current;
    setCamera(false);
    setError(null);
    setStage("connecting");
    try {
      const code = parseSetupCode(raw);
      const info = await provisioning.connect(code);
      if (current !== attempt.current) return;
      const devices = await api.listDevices();
      if (current !== attempt.current) return;
      const existing = devices.find((item) => item.id === info.deviceId);
      if (!existing && !/^[A-Za-z0-9_-]{43}$/.test(info.deviceId)) throw new Error("legacy_device");
      const found = await provisioning.scanNetworks();
      if (current !== attempt.current) return;
      setDevice(info);
      setOwned(existing !== undefined);
      if (existing) setName(existing.name);
      setNetworks(found);
      setSsid("");
      setStage("network");
    } catch (cause) {
      if (current !== attempt.current) return;
      await provisioning.cancel();
      const code = cause instanceof Error ? cause.message : "";
      setError(code === "invalid_setup_code" ? t.pair.invalidCode
        : code === "bluetooth_permission" ? t.pair.permissionError
        : code === "android_required" ? t.pair.androidRequired
        : code === "legacy_device" ? t.pair.legacyDevice
        : cause instanceof WolError ? describeError(cause) : t.pair.connectionError);
      setStage("scan");
    } finally {
      if (current === attempt.current) busy.current = false;
    }
  };

  const refresh = async () => {
    if (busy.current) return;
    busy.current = true;
    const current = attempt.current;
    setRefreshing(true);
    try {
      const found = await provisioning.scanNetworks();
      if (current === attempt.current) setNetworks(found);
    } catch {
      if (current === attempt.current) { setError(t.pair.connectionError); setStage("scan"); }
    } finally {
      if (current === attempt.current) { busy.current = false; setRefreshing(false); }
    }
  };

  const configure = async () => {
    if (busy.current || device === null) return;
    const problem = owned ? null : labelError(name);
    if (problem) { setError(problem); return; }
    if (byteLength(ssid) < 1 || byteLength(ssid) > 32 ||
        !((byteLength(password) >= 8 && byteLength(password) <= 63) || /^[0-9a-fA-F]{64}$/.test(password))) {
      setError(t.pair.networkError); return;
    }
    busy.current = true;
    const current = ++attempt.current;
    setError(null);
    setStage("configuring");
    try {
      // Claims never enter React state, clipboard, logs or persistent phone storage.
      const claim = owned ? null : await api.createClaim(name.trim(), device.deviceId);
      if (current !== attempt.current) return;
      await provisioning.configure(ssid, password, claim);
      if (current !== attempt.current) return;
      setPassword("");
      setStage("waiting");
      await provisioning.cancel();
      const deadline = Date.now() + 90_000;
      while (current === attempt.current && Date.now() < deadline) {
        const devices = await api.listDevices();
        if (current !== attempt.current) return;
        if (devices.some((item) => item.id === device.deviceId && item.online)) {
          setStage("done");
          return;
        }
        await new Promise<void>((resolve) => {
          wake.current = resolve;
          timer.current = setTimeout(() => { timer.current = null; wake.current = null; resolve(); }, 2_000);
        });
      }
      if (current === attempt.current) { setError(t.pair.confirmationTimeout); setStage("scan"); }
    } catch (cause) {
      if (current !== attempt.current) return;
      setError(cause instanceof WolError ? describeError(cause) : t.pair.connectionError);
      setStage("scan");
    } finally {
      if (current === attempt.current) {
        setPassword("");
        busy.current = false;
        await provisioning.cancel();
      }
    }
  };

  const cancel = () => { stop(); setPassword(""); router.back(); };

  return (
    <FormScreen>
      {stage === "scan" && <>
        <Muted>{t.pair.intro}</Muted>
        {camera && permission?.granted ? (
          <View style={{ height: 280, overflow: "hidden", borderRadius: 14 }}>
            <CameraView style={{ flex: 1 }} barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
              onBarcodeScanned={({ data }) => { void connect(data); }} />
          </View>
        ) : <Button title={t.pair.scan} onPress={() => { void startCamera(); }} />}
      </>}
      {stage === "connecting" && <Muted>{t.pair.connecting}</Muted>}
      {stage === "network" && <>
        {owned ? <Muted>{t.pair.wifiRecovery}</Muted> :
          <Field label={t.pair.name} value={name} onChangeText={setName} placeholder={t.pair.namePlaceholder} autoCapitalize="sentences" />}
        <Text style={styles.title}>{t.pair.chooseNetwork}</Text>
        <Muted>{t.pair.networkHint}</Muted>
        {networks.map((network) => <Button key={network.ssid} title={network.ssid} variant={ssid === network.ssid ? "primary" : "secondary"}
          disabled={refreshing} onPress={() => setSsid(network.ssid)} />)}
        <Button title={t.pair.rescan} variant="secondary" loading={refreshing} onPress={() => { void refresh(); }} />
        <Field label={t.pair.ssid} value={ssid} onChangeText={setSsid} maxLength={32} />
        <Field label={t.pair.password} value={password} onChangeText={setPassword} secureTextEntry textContentType="none" autoComplete="off" />
        <Button title={t.pair.submit} disabled={refreshing} onPress={() => { void configure(); }} />
      </>}
      {stage === "configuring" && <Muted>{t.pair.configuring}</Muted>}
      {stage === "waiting" && <Card><Muted>{t.pair.waiting}</Muted></Card>}
      {stage === "done" && <Card><Muted>{t.pair.success}</Muted></Card>}
      <ErrorText>{error}</ErrorText>
      <Button title={stage === "done" ? t.common.done : t.common.cancel} variant="secondary" onPress={cancel} />
    </FormScreen>
  );
}
