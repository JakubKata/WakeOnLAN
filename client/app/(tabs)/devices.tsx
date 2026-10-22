import { useRouter } from "expo-router";
import { useState } from "react";
import { Alert, FlatList, RefreshControl, Text, View } from "react-native";

import { api, type Device } from "@/api/client";
import { describeError } from "@/api/errors";
import { useRemote } from "@/hooks/useRemote";
import { t } from "@/i18n";
import { PromptModal } from "@/ui/PromptModal";
import { Button, Card, ErrorText, Muted, StatusDot, styles } from "@/ui/components";
import { labelError } from "@/validation";

const loadDevices = () => api.listDevices();

function lastSeen(device: Device): string {
  if (device.online) return t.common.online;
  if (device.last_seen_at === null) return t.devices.neverConnected;
  return t.devices.lastSeen(new Date(device.last_seen_at * 1000).toLocaleString(t.locale));
}

export default function DevicesScreen() {
  const router = useRouter();
  const { data, error, loading, reload } = useRemote(loadDevices);
  const [renaming, setRenaming] = useState<Device | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const remove = (device: Device) => {
    Alert.alert(
      t.devices.removeTitle,
      t.devices.removeMessage(device.name),
      [
        { text: t.common.cancel, style: "cancel" },
        {
          text: t.common.remove,
          style: "destructive",
          onPress: async () => {
            setBusyId(device.id);
            try {
              await api.removeDevice(device.id);
              await reload();
            } catch (err) {
              Alert.alert(t.common.error, describeError(err));
            } finally {
              setBusyId(null);
            }
          },
        },
      ],
    );
  };

  return (
    <>
      <FlatList
        style={styles.screen}
        contentContainerStyle={styles.listContent}
        data={data ?? []}
        keyExtractor={(device) => device.id}
        refreshControl={<RefreshControl refreshing={loading && data !== null} onRefresh={reload} />}
        ListHeaderComponent={<ErrorText>{error}</ErrorText>}
        ListEmptyComponent={
          data === null ? null : (
            <View style={styles.empty}>
              <Muted>{t.devices.empty}</Muted>
              <Button title={t.devices.pair} onPress={() => router.push("/device/pair")} />
            </View>
          )
        }
        renderItem={({ item }) => (
          <Card>
            <View style={styles.row}>
              <StatusDot online={item.online} />
              <Text style={[styles.title, { flex: 1 }]}>{item.name}</Text>
            </View>
            <Muted>{lastSeen(item)}</Muted>
            <View style={styles.actions}>
              <Button title={t.devices.rename} variant="secondary" onPress={() => setRenaming(item)} disabled={busyId !== null} />
              <Button title={t.common.remove} variant="danger" onPress={() => remove(item)} disabled={busyId !== null} />
            </View>
          </Card>
        )}
      />
      <PromptModal
        visible={renaming !== null}
        title={t.devices.renameTitle}
        fields={[{ key: "name", label: t.common.name, initial: renaming?.name }]}
        onClose={() => setRenaming(null)}
        onSubmit={async ({ name }) => {
          const problem = labelError(name);
          if (problem) throw new Error(problem);
          await api.renameDevice(renaming!.id, name.trim());
          await reload();
        }}
      />
    </>
  );
}
