import { Pressable, Text, View } from "react-native";

import type { Device } from "@/api/client";
import { t } from "@/i18n";

import { Muted, StatusDot, styles } from "./components";
import { colors, spacing } from "./theme";

export function DevicePicker({
  devices,
  selected,
  onSelect,
}: {
  devices: Device[];
  selected: string | null;
  onSelect: (deviceId: string) => void;
}) {
  if (devices.length === 0) {
    return <Muted>{t.devicePicker.none}</Muted>;
  }
  return (
    <View style={{ gap: spacing.sm }}>
      <Text style={styles.label}>{t.devicePicker.label}</Text>
      {devices.map((device) => {
        const active = device.id === selected;
        return (
          <Pressable
            key={device.id}
            onPress={() => onSelect(device.id)}
            style={[
              styles.card,
              styles.row,
              { paddingVertical: spacing.md },
              active && { borderColor: colors.primary, borderWidth: 2 },
            ]}
          >
            <StatusDot online={device.online} />
            <Text style={{ flex: 1, fontSize: 16, color: colors.text }}>{device.name}</Text>
            {active ? <Text style={{ color: colors.primary, fontWeight: "600" }}>{t.devicePicker.selected}</Text> : null}
          </Pressable>
        );
      })}
    </View>
  );
}
