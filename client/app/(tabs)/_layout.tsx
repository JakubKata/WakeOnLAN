import { Ionicons } from "@expo/vector-icons";
import { Link, Tabs } from "expo-router";
import type { ComponentProps } from "react";
import { Pressable, Text } from "react-native";

import { t } from "@/i18n";
import { colors } from "@/ui/theme";

type IconName = ComponentProps<typeof Ionicons>["name"];

function icon(name: IconName) {
  return ({ color, size }: { color: string; size: number }) => <Ionicons name={name} color={color} size={size} />;
}

function HeaderLink({ href, title }: { href: "/target/new" | "/device/pair"; title: string }) {
  return (
    <Link href={href} asChild>
      <Pressable hitSlop={12} style={{ paddingHorizontal: 16 }}>
        <Text style={{ color: colors.primary, fontSize: 16, fontWeight: "600" }}>{title}</Text>
      </Pressable>
    </Link>
  );
}

export default function TabsLayout() {
  return (
    <Tabs screenOptions={{ tabBarActiveTintColor: colors.primary, sceneStyle: { backgroundColor: colors.background } }}>
      <Tabs.Screen
        name="index"
        options={{
          title: t.screens.targets,
          tabBarIcon: icon("desktop-outline"),
          headerRight: () => <HeaderLink href="/target/new" title={t.screens.add} />,
        }}
      />
      <Tabs.Screen
        name="devices"
        options={{
          title: t.screens.devices,
          tabBarIcon: icon("hardware-chip-outline"),
          headerRight: () => <HeaderLink href="/device/pair" title={t.screens.pair} />,
        }}
      />
      <Tabs.Screen name="account" options={{ title: t.screens.account, tabBarIcon: icon("person-outline") }} />
    </Tabs>
  );
}
