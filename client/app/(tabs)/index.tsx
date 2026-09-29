import { useRouter } from "expo-router";
import { useState } from "react";
import { Alert, FlatList, Pressable, RefreshControl, Text, View } from "react-native";

import { api, type Device, type Target } from "@/api/client";
import { describeError } from "@/api/errors";
import { useRemote } from "@/hooks/useRemote";
import { t } from "@/i18n";
import { Button, Card, ErrorText, Muted, StatusDot, styles } from "@/ui/components";

const loadPanel = () => Promise.all([api.listTargets(), api.listDevices()]);

export default function TargetsScreen() {
  const router = useRouter();
  const { data, error, loading, reload } = useRemote(loadPanel);
  const [waking, setWaking] = useState<number | null>(null);

  const targets = data?.[0] ?? [];
  const devices = new Map((data?.[1] ?? []).map((device) => [device.id, device]));

  const wake = async (target: Target) => {
    setWaking(target.id);
    try {
      await api.wakeUp(target.id);
      Alert.alert(t.targets.sentTitle, t.targets.sent(target.name));
    } catch (err) {
      Alert.alert(t.targets.wakeFailed, describeError(err));
      void reload();
    } finally {
      setWaking(null);
    }
  };

  return (
    <FlatList
      style={styles.screen}
      contentContainerStyle={styles.listContent}
      data={targets}
      keyExtractor={(target) => String(target.id)}
      refreshControl={<RefreshControl refreshing={loading && data !== null} onRefresh={reload} />}
      ListHeaderComponent={<ErrorText>{error}</ErrorText>}
      ListEmptyComponent={
        data === null ? null : (
          <View style={styles.empty}>
            <Muted>{t.targets.empty}</Muted>
            <Button title={t.targets.add} onPress={() => router.push("/target/new")} />
          </View>
        )
      }
      renderItem={({ item }) => (
        <TargetCard
          target={item}
          device={item.device_id ? devices.get(item.device_id) : undefined}
          waking={waking === item.id}
          disabled={waking !== null}
          onWake={() => wake(item)}
          onEdit={() => router.push({ pathname: "/target/[id]", params: { id: String(item.id) } })}
        />
      )}
    />
  );
}

function TargetCard({
  target,
  device,
  waking,
  disabled,
  onWake,
  onEdit,
}: {
  target: Target;
  device: Device | undefined;
  waking: boolean;
  disabled: boolean;
  onWake: () => void;
  onEdit: () => void;
}) {
  return (
    <Card>
      <Pressable onPress={onEdit} style={{ gap: 4 }}>
        <Text style={styles.title}>{target.name}</Text>
        <Muted>{target.mac}</Muted>
        <View style={styles.row}>
          {device ? <StatusDot online={device.online} /> : null}
          <Muted>
            {device ? `${device.name} · ${device.online ? t.common.online : t.common.offline}` : t.targets.noDevice}
          </Muted>
        </View>
      </Pressable>
      <Button
        title={t.targets.wake}
        onPress={onWake}
        loading={waking}
        disabled={disabled || !device}
        style={{ marginTop: 12, minHeight: 52 }}
      />
    </Card>
  );
}
