import { useFocusEffect } from "expo-router";
import { useCallback, useRef, useState } from "react";

import { describeError } from "@/api/errors";

/** Loads server data whenever the screen gains focus; `load` must be stable. */
export function useRemote<T>(load: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const generation = useRef(0);

  const reload = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    try {
      const result = await load();
      if (current !== generation.current) return;
      setData(result);
      setError(null);
    } catch (err) {
      if (current === generation.current) setError(describeError(err));
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [load]);

  useFocusEffect(
    useCallback(() => {
      void reload();
    }, [reload]),
  );

  return { data, error, loading, reload };
}
