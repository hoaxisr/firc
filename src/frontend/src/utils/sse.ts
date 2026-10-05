export type SseEvent = { event: string; data: string };

const LINE_BREAK = /\r\n|\n|\r/;

export async function* readEvents(response: Response): AsyncGenerator<SseEvent> {
  const body = response.body;
  if (!body) return;

  const reader = body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";
  let name = "";
  let data: string[] = [];
  const ready: SseEvent[] = [];

  const field = (line: string) => {
    if (line === "") {
      if (name !== "" || data.length > 0) {
        ready.push({ event: name || "message", data: data.join("\n") });
      }
      name = "";
      data = [];
      return;
    }
    if (line.startsWith(":")) return;

    const colon = line.indexOf(":");
    const key = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);

    if (key === "event") name = value;
    else if (key === "data") data.push(value);
  };

  const consume = (final: boolean) => {
    for (;;) {
      const match = LINE_BREAK.exec(buffer);
      if (!match) return;
      /* A trailing \r is held: its \n may start the next chunk. */
      if (!final && match[0] === "\r" && match.index === buffer.length - 1) return;
      field(buffer.slice(0, match.index));
      buffer = buffer.slice(match.index + match[0].length);
    }
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      consume(false);
      while (ready.length > 0) yield ready.shift() as SseEvent;
    }

    buffer += decoder.decode();
    consume(true);
    while (ready.length > 0) yield ready.shift() as SseEvent;
  } finally {
    void reader.cancel().catch(() => {});
  }
}
