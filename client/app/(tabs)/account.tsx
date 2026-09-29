import { useState } from "react";
import { Alert, Text } from "react-native";

import { describeError } from "@/api/errors";
import { useAsyncAction } from "@/hooks/useAsyncAction";
import { t } from "@/i18n";
import { useSession } from "@/session/SessionProvider";
import { PromptModal, type PromptField } from "@/ui/PromptModal";
import { Button, Card, ErrorText, FormScreen, Muted, serverLabel, styles } from "@/ui/components";
import { passwordError, usernameError } from "@/validation";

type Dialog = "name" | "password" | "delete" | null;

export default function AccountScreen() {
  const session = useSession();
  const [dialog, setDialog] = useState<Dialog>(null);
  const logout = useAsyncAction();

  const logoutAll = () => {
    Alert.alert(t.account.logoutAllTitle, t.account.logoutAllMessage, [
      { text: t.common.cancel, style: "cancel" },
      {
        text: t.account.logout,
        style: "destructive",
        onPress: () => session.logoutAll().catch((err) => Alert.alert(t.common.error, describeError(err))),
      },
    ]);
  };

  const dialogs: Record<Exclude<Dialog, null>, {
    title: string;
    message?: string;
    fields: PromptField[];
    confirmLabel?: string;
    destructive?: boolean;
    submit: (values: Record<string, string>) => Promise<void>;
  }> = {
    name: {
      title: t.account.changeName,
      fields: [
        { key: "name", label: t.account.newName, initial: session.userName ?? "" },
        { key: "password", label: t.common.password, secure: true },
      ],
      async submit({ name, password }) {
        const problem = usernameError(name.trim());
        if (problem) throw new Error(problem);
        await session.changeName(name.trim(), password);
      },
    },
    password: {
      title: t.account.changePassword,
      message: t.account.changePasswordMessage,
      fields: [
        { key: "old", label: t.account.currentPassword, secure: true },
        { key: "new", label: t.common.newPassword, secure: true },
        { key: "repeat", label: t.account.repeatNewPassword, secure: true },
      ],
      async submit(values) {
        const problem = passwordError(values.new) ?? (values.new !== values.repeat ? t.common.passwordsDiffer : null);
        if (problem) throw new Error(problem);
        await session.changePassword(values.old, values.new);
        Alert.alert(t.common.done, t.account.passwordChanged);
      },
    },
    delete: {
      title: t.account.deleteAccount,
      message: t.account.deleteMessage,
      fields: [{ key: "password", label: t.common.password, secure: true }],
      confirmLabel: t.account.deleteAccount,
      destructive: true,
      async submit({ password }) {
        await session.deleteAccount(password);
      },
    },
  };
  const active = dialog ? dialogs[dialog] : null;

  return (
    <FormScreen>
      <Card style={{ gap: 4 }}>
        <Muted>{t.account.signedInAs}</Muted>
        <Text style={styles.title}>{session.userName ?? "..."}</Text>
        <Muted>{serverLabel(session.server)}</Muted>
      </Card>
      <Button title={t.account.changeName} variant="secondary" onPress={() => setDialog("name")} />
      <Button title={t.account.changePassword} variant="secondary" onPress={() => setDialog("password")} />
      <Button
        title={t.account.logout}
        variant="secondary"
        onPress={() => void logout.run(session.logout)}
        loading={logout.busy}
      />
      <ErrorText>{logout.error}</ErrorText>
      <Button title={t.account.logoutAll} variant="secondary" onPress={logoutAll} />
      <Button title={t.account.deleteAccount} variant="danger" onPress={() => setDialog("delete")} />

      <PromptModal
        visible={active !== null}
        title={active?.title ?? ""}
        message={active?.message}
        fields={active?.fields ?? []}
        confirmLabel={active?.confirmLabel}
        destructive={active?.destructive}
        onClose={() => setDialog(null)}
        onSubmit={async (values) => {
          if (active) await active.submit(values);
        }}
      />
    </FormScreen>
  );
}
