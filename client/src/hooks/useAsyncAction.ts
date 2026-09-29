import { useCallback, useState } from "react";

import { describeError } from "@/api/errors";

/** Busy flag and error message for a form's submit action. */
export function useAsyncAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /** Runs `action`, showing its error; resolves to whether it succeeded. */
  const run = useCallback(async (action: () => Promise<unknown>): Promise<boolean> => {
    setError(null);
    setBusy(true);
    try {
      await action();
      return true;
    } catch (err) {
      setError(describeError(err));
      return false;
    } finally {
      setBusy(false);
    }
  }, []);

  return { busy, error, setError, run };
}
