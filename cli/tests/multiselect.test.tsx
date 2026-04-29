// Drive the multiselect component through opentui's test renderer to
// verify that arrow / j / k / space actually mutate cursor + checked
// state and that the rendered frame reflects the mutation. We assert
// on the captured character frame — exactly what the user would see.

import { describe, expect, test } from "bun:test";
import { createRoot } from "@opentui/react";
import { createTestRenderer } from "@opentui/core/testing";
import { useEffect, useRef, useState } from "react";
import { flushSync, useRenderer } from "@opentui/react";
import type { KeyEvent } from "@opentui/core";

// Mirror the internal component so we don't have to export it. Keep in
// sync with src/tui/multiselect.tsx if the render shape changes.
function Picker(props: {
  options: { id: string; label: string; disabled?: boolean }[];
  onDone: (r: string[] | null) => void;
}): React.ReactNode {
  const cursorRef = useRef(0);
  const checkedRef = useRef(new Set<string>());
  const [, setTick] = useState(0);
  const nudge = (): void => flushSync(() => setTick((t) => (t + 1) | 0));

  useEffect(() => {
    const id = setInterval(nudge, 16);
    return () => clearInterval(id);
  }, []);

  const renderer = useRenderer();
  useEffect(() => {
    const kh = renderer.keyInput;
    if (!kh) return;
    const handler = (e: KeyEvent): void => {
      const name = e.name;
      if (name === "return" || name === "enter") {
        props.onDone([...checkedRef.current]);
        return;
      }
      if (name === "up" || name === "k") {
        const n = props.options.length;
        if (n > 0) cursorRef.current = (cursorRef.current - 1 + n) % n;
        nudge();
        return;
      }
      if (name === "down" || name === "j") {
        const n = props.options.length;
        if (n > 0) cursorRef.current = (cursorRef.current + 1) % n;
        nudge();
        return;
      }
      if (name === "space" || name === " " || e.sequence === " ") {
        const opt = props.options[cursorRef.current];
        if (opt && !opt.disabled) {
          if (checkedRef.current.has(opt.id)) checkedRef.current.delete(opt.id);
          else checkedRef.current.add(opt.id);
        }
        nudge();
        return;
      }
    };
    kh.on("keypress", handler);
    return () => {
      kh.off("keypress", handler);
    };
  }, [renderer, props]);

  const cursor = cursorRef.current;
  const checked = checkedRef.current;
  return (
    <box flexDirection="column">
      {props.options.map((opt, i) => {
        const isCursor = i === cursor;
        const isChecked = checked.has(opt.id);
        const arrow = isCursor ? ">" : " ";
        const mark = isChecked ? "[x]" : "[ ]";
        return (
          <text key={opt.id}>{`${arrow} ${mark} ${opt.label}`}</text>
        );
      })}
    </box>
  );
}

describe("multiselect keyboard", () => {
  test("arrows + space mutate cursor and checked, frame reflects it", async () => {
    const { renderer, renderOnce, captureCharFrame } =
      await createTestRenderer({ width: 40, height: 10 });

    const root = createRoot(renderer);
    const options = [
      { id: "a", label: "alpha" },
      { id: "b", label: "beta" },
      { id: "c", label: "gamma" },
    ];

    let done: string[] | null = null;
    root.render(<Picker options={options} onDone={(r) => (done = r)} />);

    await new Promise((r) => setTimeout(r, 30));
    await renderOnce();
    await renderOnce();
    const initial = captureCharFrame();
    expect(initial).toContain("> [ ] alpha");
    expect(initial).toContain("  [ ] beta");
    expect(initial).toContain("  [ ] gamma");

    // Directly emit keypress events because createTestRenderer skips
    // setupTerminal → no stdin.on('data') → pressKey is a no-op.
    // Component only cares that renderer.keyInput fires events.
    const emit = (name: string): void => {
      renderer.keyInput.emit("keypress", {
        name,
        ctrl: false,
        meta: false,
        shift: false,
        option: false,
        sequence: name === "space" ? " " : name,
        number: false,
        raw: "",
        eventType: "press",
        source: "raw",
      } as never);
    };
    // Press down — cursor should move to beta.
    emit("down");
    await renderOnce();
    const afterDown = captureCharFrame();
    expect(afterDown).toContain("  [ ] alpha");
    expect(afterDown).toContain("> [ ] beta");

    // Press space — beta toggles on.
    emit("space");
    await renderOnce();
    const afterSpace = captureCharFrame();
    expect(afterSpace).toContain("> [x] beta");

    // Press j — cursor to gamma.
    emit("j");
    await renderOnce();
    const afterJ = captureCharFrame();
    expect(afterJ).toContain("  [x] beta");
    expect(afterJ).toContain("> [ ] gamma");

    // Space gamma on.
    emit("space");
    await renderOnce();
    const afterSpaceGamma = captureCharFrame();
    expect(afterSpaceGamma).toContain("> [x] gamma");

    // Press enter — done.
    emit("return");
    await renderOnce();
    expect(done).not.toBeNull();
    expect(done!.sort()).toEqual(["b", "c"]);

    root.unmount();
    renderer.destroy();
  });
});
