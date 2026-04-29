// Minimal stdin prompt helpers. Used by `agentlock login` and the
// install flow. Hides the password echo where possible by toggling
// raw mode on the TTY — falls back to plain-echo when stdin isn't a
// TTY (CI, piped input) so scripts still work.

import { createInterface } from "node:readline";

export async function readPrompt(label: string): Promise<string> {
  process.stdout.write(label);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return await new Promise<string>((resolve) => {
    rl.once("line", (line) => {
      rl.close();
      resolve(line.trim());
    });
  });
}

export async function readPassword(label: string): Promise<string> {
  process.stdout.write(label);
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    // Not a TTY — fall back to plain readline; scripts can still feed
    // the password via heredoc.
    const rl = createInterface({ input: stdin, output: process.stdout });
    return await new Promise<string>((resolve) => {
      rl.once("line", (line) => {
        rl.close();
        resolve(line);
      });
    });
  }
  return await new Promise<string>((resolve, reject) => {
    let buf = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (ch: string): void => {
      for (const c of ch) {
        if (c === "\n" || c === "\r") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          resolve(buf);
          return;
        }
        if (c === "") {
          // Ctrl-C
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener("data", onData);
          reject(new Error("aborted"));
          return;
        }
        if (c === "" || c === "\b") {
          buf = buf.slice(0, -1);
          continue;
        }
        buf += c;
      }
    };
    stdin.on("data", onData);
  });
}
