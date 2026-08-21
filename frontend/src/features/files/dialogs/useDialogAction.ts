import { useCallback, useState } from "react";
import { errMessage } from "../formatters";

export function useDialogAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(
    async (action: () => Promise<void>) => {
      if (busy) return;
      setBusy(true);
      setError(null);
      try {
        await action();
      } catch (cause) {
        setError(errMessage(cause));
        setBusy(false);
      }
    },
    [busy],
  );
  return { busy, error, run };
}
