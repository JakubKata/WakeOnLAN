import { useEffect, useState } from "react";
import { KeyboardAvoidingView, Modal, Platform, StyleSheet, Text, View } from "react-native";

import { describeError } from "@/api/errors";
import { t } from "@/i18n";

import { Button, ErrorText, Field, styles } from "./components";
import { colors, spacing } from "./theme";

export interface PromptField {
  key: string;
  label: string;
  secure?: boolean;
  initial?: string;
}

/** Android has no Alert.prompt, so text input dialogs go through this modal. */
export function PromptModal({
  visible,
  title,
  message,
  fields,
  confirmLabel = t.common.save,
  destructive = false,
  onSubmit,
  onClose,
}: {
  visible: boolean;
  title: string;
  message?: string;
  fields: PromptField[];
  confirmLabel?: string;
  destructive?: boolean;
  onSubmit: (values: Record<string, string>) => Promise<void>;
  onClose: () => void;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!visible) return;
    setValues(Object.fromEntries(fields.map((field) => [field.key, field.initial ?? ""])));
    setError(null);
    // Reset only when the dialog opens, not on every parent render.
  }, [visible]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(values);
      onClose();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <KeyboardAvoidingView style={local.backdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={local.dialog}>
          <Text style={styles.title}>{title}</Text>
          {message ? <Text style={local.message}>{message}</Text> : null}
          {fields.map((field, index) => (
            <Field
              key={field.key}
              label={field.label}
              value={values[field.key] ?? ""}
              secureTextEntry={field.secure}
              autoFocus={index === 0}
              onChangeText={(text) => setValues((current) => ({ ...current, [field.key]: text }))}
            />
          ))}
          <ErrorText>{error}</ErrorText>
          <View style={local.buttons}>
            <Button title={t.common.cancel} variant="secondary" onPress={onClose} disabled={busy} style={local.button} />
            <Button
              title={confirmLabel}
              variant={destructive ? "danger" : "primary"}
              onPress={submit}
              loading={busy}
              style={local.button}
            />
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const local = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.4)", justifyContent: "center", padding: spacing.xl },
  dialog: { backgroundColor: colors.surface, borderRadius: 16, padding: spacing.lg, gap: spacing.md },
  message: { fontSize: 14, color: colors.muted },
  buttons: { flexDirection: "row", gap: spacing.sm, justifyContent: "flex-end" },
  button: { flex: 1 },
});
