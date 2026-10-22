import { requireNativeModule } from "expo-modules-core";
import { PermissionsAndroid, Platform } from "react-native";

export interface SetupCode {
  ver: "v1";
  name: string;
  transport: "ble";
  security: 2;
  username: string;
  pop: string;
}

export interface DeviceInfo {
  deviceId: string;
  paired: boolean;
}

export interface WifiNetwork {
  ssid: string;
  rssi: number;
}

interface NativeProvisioning {
  connect(name: string, username: string, password: string): Promise<DeviceInfo>;
  scanNetworks(): Promise<WifiNetwork[]>;
  configure(ssid: string, password: string, token: string | null, unixTime: number): Promise<void>;
  cancel(): Promise<void>;
}

export function parseSetupCode(raw: string): SetupCode {
  if (raw.length > 1024) throw new Error("invalid_setup_code");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error("invalid_setup_code"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid_setup_code");
  const code = value as Record<string, unknown>;
  if (code.ver !== "v1" || code.transport !== "ble" || code.security !== 2 ||
      typeof code.name !== "string" || !/^WOL_[A-Za-z0-9_-]{6,40}$/.test(code.name) ||
      typeof code.username !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(code.username) ||
      typeof code.pop !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(code.pop)) {
    throw new Error("invalid_setup_code");
  }
  return code as unknown as SetupCode;
}

function native(): NativeProvisioning {
  if (Platform.OS !== "android") throw new Error("android_required");
  return requireNativeModule<NativeProvisioning>("WolProvisioning");
}

async function bluetoothPermission(): Promise<void> {
  if (Platform.OS !== "android") throw new Error("android_required");
  const required = Number(Platform.Version) >= 31
    ? [PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN, PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT]
    : [PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION];
  const result = await PermissionsAndroid.requestMultiple(required);
  if (required.some((permission) => result[permission] !== PermissionsAndroid.RESULTS.GRANTED)) {
    throw new Error("bluetooth_permission");
  }
}

export const provisioning = {
  async connect(code: SetupCode): Promise<DeviceInfo> {
    await bluetoothPermission();
    return native().connect(code.name, code.username, code.pop);
  },
  scanNetworks: () => native().scanNetworks(),
  configure: (ssid: string, password: string, token: string | null) =>
    native().configure(ssid, password, token, Math.floor(Date.now() / 1000)),
  async cancel(): Promise<void> {
    try { await native().cancel(); } catch { /* A missing module or closed screen has no BLE session. */ }
  },
};
