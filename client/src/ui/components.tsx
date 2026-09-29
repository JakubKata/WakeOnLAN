import type { ReactNode } from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputProps,
  type ViewStyle,
} from "react-native";

import type { ServerAddress } from "@/api/client";
import { t } from "@/i18n";

import { colors, spacing } from "./theme";

export function serverLabel(server: ServerAddress): string {
  return t.common.server(`${server.host || t.common.notSet}:${server.port}`);
}

type ButtonVariant = "primary" | "secondary" | "danger";

export function Button({
  title,
  onPress,
  variant = "primary",
  loading = false,
  disabled = false,
  style,
}: {
  title: string;
  onPress: () => void;
  variant?: ButtonVariant;
  loading?: boolean;
  disabled?: boolean;
  style?: ViewStyle;
}) {
  const inactive = disabled || loading;
  const textColor = variant === "primary" ? colors.primaryText : variant === "danger" ? colors.danger : colors.primary;
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      disabled={inactive}
      style={({ pressed }) => [
        styles.button,
        variant === "primary" ? styles.buttonPrimary : styles.buttonOutline,
        variant === "danger" && styles.buttonDanger,
        (pressed || inactive) && styles.buttonDimmed,
        style,
      ]}
    >
      {loading ? <ActivityIndicator color={textColor} /> : <Text style={[styles.buttonText, { color: textColor }]}>{title}</Text>}
    </Pressable>
  );
}

export function Field({ label, ...props }: TextInputProps & { label: string }) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        autoCapitalize="none"
        autoCorrect={false}
        placeholderTextColor={colors.muted}
        {...props}
        style={[styles.input, props.style]}
      />
    </View>
  );
}

export function Card({ children, style }: { children: ReactNode; style?: ViewStyle }) {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function ErrorText({ children }: { children: string | null | undefined }) {
  if (!children) return null;
  return <Text style={styles.error}>{children}</Text>;
}

export function Muted({ children }: { children: ReactNode }) {
  return <Text style={styles.muted}>{children}</Text>;
}

export function FormScreen({ children }: { children: ReactNode }) {
  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.formContent} keyboardShouldPersistTaps="handled">
      {children}
    </ScrollView>
  );
}

export function StatusDot({ online }: { online: boolean }) {
  return <View style={[styles.dot, { backgroundColor: online ? colors.success : colors.offline }]} />;
}

export const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.background },
  formContent: { padding: spacing.lg, gap: spacing.md },
  listContent: { padding: spacing.lg, gap: spacing.md, flexGrow: 1 },
  title: { fontSize: 18, fontWeight: "600", color: colors.text },
  heading: { fontSize: 24, fontWeight: "700", color: colors.text, marginBottom: spacing.sm },
  row: { flexDirection: "row", alignItems: "center", gap: spacing.sm },
  actions: { flexDirection: "row", flexWrap: "wrap", gap: spacing.sm, marginTop: spacing.md },
  button: {
    minHeight: 44,
    paddingHorizontal: spacing.lg,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
  },
  buttonPrimary: { backgroundColor: colors.primary },
  buttonOutline: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.primary },
  buttonDanger: { borderColor: colors.danger },
  buttonDimmed: { opacity: 0.6 },
  buttonText: { fontSize: 16, fontWeight: "600" },
  field: { gap: spacing.xs },
  label: { fontSize: 14, color: colors.muted },
  input: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    fontSize: 16,
    color: colors.text,
  },
  card: {
    backgroundColor: colors.surface,
    borderRadius: 14,
    padding: spacing.lg,
    borderWidth: 1,
    borderColor: colors.border,
  },
  error: { color: colors.danger, fontSize: 14 },
  muted: { color: colors.muted, fontSize: 14 },
  link: { color: colors.primary, textAlign: "center", padding: spacing.sm },
  dot: { width: 10, height: 10, borderRadius: 5 },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", gap: spacing.md, padding: spacing.xl },
});
