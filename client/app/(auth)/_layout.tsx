import { Stack } from "expo-router";

import { t } from "@/i18n";
import { colors } from "@/ui/theme";

export default function AuthLayout() {
  return (
    <Stack screenOptions={{ contentStyle: { backgroundColor: colors.background } }}>
      <Stack.Screen name="login" options={{ title: t.screens.login }} />
      <Stack.Screen name="register" options={{ title: t.screens.register }} />
      <Stack.Screen name="reset" options={{ title: t.screens.reset }} />
    </Stack>
  );
}
