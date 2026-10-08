export type Ask = {
  title: string;
  message: string;
  items?: string[];
  confirm: string;
  tone: "danger" | "warn";
};

type Pending = Ask & { resolve: (ok: boolean) => void };

export const confirmation = $state<{ current: Pending | null }>({ current: null });

export function ask(question: Ask): Promise<boolean> {
  confirmation.current?.resolve(false);
  return new Promise((resolve) => {
    confirmation.current = { ...question, resolve };
  });
}

export function answer(ok: boolean) {
  const pending = confirmation.current;
  confirmation.current = null;
  pending?.resolve(ok);
}
