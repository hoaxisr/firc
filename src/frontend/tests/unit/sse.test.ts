import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { readEvents } from "../../src/utils/sse";

const encoder = new TextEncoder();

function responseOf(...chunks: string[]): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return { body } as unknown as Response;
}

async function collect(response: Response) {
  const events: { event: string; data: string }[] = [];
  for await (const event of readEvents(response)) events.push(event);
  return events;
}

describe("server-sent events", () => {
  // Catches a parser treating one chunk as one message.
  it("an event split across chunk boundaries is one event", async () => {
    const events = await collect(
      responseOf("event: prog", 'ress\ndata: {"stage":"fetch",', '"bytes":100}\n\n'),
    );

    assert.deepStrictEqual(events, [{ event: "progress", data: '{"stage":"fetch","bytes":100}' }]);
  });

  // Catches a parser dropping every frame after the first in a chunk.
  it("two events in one chunk are two events", async () => {
    const events = await collect(
      responseOf(
        'event: progress\ndata: {"stage":"apply"}\n\nevent: done\ndata: {"id":"a1b2c3d4"}\n\n',
      ),
    );

    assert.deepStrictEqual(events, [
      { event: "progress", data: '{"stage":"apply"}' },
      { event: "done", data: '{"id":"a1b2c3d4"}' },
    ]);
  });

  // Catches a ':' comment line (the proxy keep-alive) read as an event.
  it("a comment line is not an event", async () => {
    const events = await collect(responseOf(":keep-alive\n\n", "event: done\ndata: {}\n\n"));

    assert.deepStrictEqual(events, [{ event: "done", data: "{}" }]);
  });

  // Catches splitting on every colon, or keeping the space after it, which corrupts the JSON.
  it("a data payload keeps its colons and loses only the separator space", async () => {
    const events = await collect(
      responseOf('event: error\ndata: {"error":"fetch failed: HTTP 404"}\n\n'),
    );

    assert.deepStrictEqual(events, [
      { event: "error", data: '{"error":"fetch failed: HTTP 404"}' },
    ]);
  });

  // Catches data: lines joined with nothing or only the last kept; they join with a newline.
  it("two data lines are one payload", async () => {
    const events = await collect(responseOf("event: done\ndata: one\ndata: two\n\n"));

    assert.deepStrictEqual(events, [{ event: "done", data: "one\ntwo" }]);
  });

  // Catches splitting on "\n" alone, leaving "\r" on every value so the event name never matches.
  it("an event delimited by CRLF is one event", async () => {
    const events = await collect(responseOf("event: done\r\ndata: {}\r\n\r\n"));

    assert.deepStrictEqual(events, [{ event: "done", data: "{}" }]);
  });

  // Catches a trailing "\r" treated as a finished line, dispatching `done` with no data.
  it("a CRLF split across chunks is one line break", async () => {
    const events = await collect(responseOf("event: done\r", '\ndata: {"rulesTotal":3}\r\n\r\n'));

    assert.deepStrictEqual(events, [{ event: "done", data: '{"rulesTotal":3}' }]);
  });

  // Catches a truncated event flushed at stream end; the drop must reopen the stream instead.
  it("an event cut off by the end of the stream is discarded", async () => {
    const events = await collect(responseOf('event: done\ndata: {"rulesTo'));

    assert.deepStrictEqual(events, []);
  });
});
