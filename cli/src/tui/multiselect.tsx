// OpenTUI + React multi-select.
//
// Design rationale: opentui's custom reconciler under React 19 needs an
// explicit kick to commit state updates that originate inside a raw
// keypress callback. Without that, the handler fires but the terminal
// never repaints — symptom is "arrows do nothing." Three pieces working
// together fix it:
//   1. Mutable refs for cursor + checked. Reads during render see the
//      latest value the handler just wrote.
//   2. A tiny `tick` useState whose only job is to invalidate the tree.
//      `nudge()` wraps `setTick` in `flushSync`, which forces the
//      reconciler to commit synchronously inside the keypress turn.
//   3. Direct `renderer.keyInput.on("keypress", …)` via `useRenderer`
//      rather than the `useKeyboard` hook. The hook routes events
//      through `useEffectEvent`, which (in this React 19 + opentui
//      combo) sometimes drops the very first events while the effect
//      ref is still settling.
// Verified end-to-end against a real PTY by scripts/repro-multiselect.sh
// and scripts/repro-install-e2e.sh.

import { createCliRenderer, type KeyEvent } from "@opentui/core";
import { createRoot, flushSync, useRenderer } from "@opentui/react";
import { useEffect, useRef, useState } from "react";

export interface Option<T> {
  id: T;
  label: string;
  sub?: string;
  checked?: boolean;
  disabled?: boolean;
  disabledReason?: string;
}

export interface MultiselectOptions<T> {
  title: string;
  options: Option<T>[];
}

interface AppProps<T extends string> {
  title: string;
  options: Option<T>[];
  onDone: (result: T[] | null) => void;
}

const DEBUG = process.env.AGENTLOCK_TUI_DEBUG === "1";

function firstEnabledIndex<T>(options: Option<T>[]): number {
  for (let i = 0; i < options.length; i++) {
    if (!options[i]?.disabled) return i;
  }
  return 0;
}

// toggleAll flips the checked set: all-on if the enabled rows are not
// already all-on, otherwise clears. Mutates the ref in place so the next
// render (driven by nudge()) sees the new set.
function toggleAll<T>(
  options: Option<T>[],
  checkedRef: { current: Set<T> },
): void {
  const enabled = options.filter((o) => !o.disabled);
  const allOn =
    enabled.length > 0 && enabled.every((o) => checkedRef.current.has(o.id));
  const next = new Set<T>();
  if (!allOn) for (const o of enabled) next.add(o.id);
  checkedRef.current = next;
}

function MultiselectApp<T extends string>({
  title,
  options,
  onDone,
}: AppProps<T>): React.ReactNode {
  const cursorRef = useRef(firstEnabledIndex(options));
  const checkedRef = useRef(
    new Set<T>(
      options.filter((o) => o.checked && !o.disabled).map((o) => o.id),
    ),
  );
  const lastKeyRef = useRef("");

  // Proven-to-work pattern (verified by tests/multiselect.test.tsx):
  //   1. Mutable refs for cursor/checked — reads during render.
  //   2. nudge() wraps setTick in flushSync so React commits the
  //      tick-bump synchronously. Without flushSync the opentui
  //      reconciler queues the update but never repaints under
  //      keyboard-driven flows, which is exactly the "keys fire but
  //      nothing moves" report.
  //   3. Direct renderer.keyInput subscription. The useKeyboard hook
  //      goes through a useEffectEvent wrapper that has intermittent
  //      issues on real-terminal runs.
  const [, setTick] = useState(0);
  const nudge = (): void => flushSync(() => setTick((t) => (t + 1) | 0));

  const renderer = useRenderer();
  useEffect(() => {
    const kh = renderer.keyInput;
    if (!kh) return;
    const handler = (e: KeyEvent): void => {
      const name = e.name;
      if (DEBUG) lastKeyRef.current = `${name}${e.ctrl ? " (ctrl)" : ""}`;

      if (name === "escape" || name === "q") {
        onDone(null);
        return;
      }
      if (name === "return" || name === "enter") {
        onDone([...checkedRef.current]);
        return;
      }
      if (name === "up" || name === "k") {
        const n = options.length;
        if (n > 0) cursorRef.current = (cursorRef.current - 1 + n) % n;
        nudge();
        return;
      }
      if (name === "down" || name === "j") {
        const n = options.length;
        if (n > 0) cursorRef.current = (cursorRef.current + 1) % n;
        nudge();
        return;
      }
      if (name === "space" || name === " " || e.sequence === " ") {
        const opt = options[cursorRef.current];
        if (opt && !opt.disabled) {
          if (checkedRef.current.has(opt.id)) checkedRef.current.delete(opt.id);
          else checkedRef.current.add(opt.id);
        }
        nudge();
        return;
      }
      // `a` and `A` (shift+a) both toggle-all. We tried shift+space too
      // but most terminals don't forward the shift modifier on space, so
      // it never triggers reliably. The letter binding is portable.
      if (name === "a" || name === "A") {
        toggleAll(options, checkedRef);
        nudge();
        return;
      }
    };
    kh.on("keypress", handler);
    return () => {
      kh.off("keypress", handler);
    };
  }, [renderer, options, onDone]);

  const cursor = cursorRef.current;
  const checked = checkedRef.current;

  return (
    <box padding={1} flexDirection="column">
      <text fg="white" attributes={1}>
        {title}
      </text>
      <text> </text>
      {options.map((opt, i) => {
        const isCursor = i === cursor;
        const isChecked = checked.has(opt.id);
        const arrow = isCursor ? ">" : " ";
        const mark = isChecked ? "[x]" : "[ ]";
        const baseColor = opt.disabled ? "#666666" : "#CCCCCC";
        const cursorColor = isCursor ? "#00FFAA" : baseColor;
        const note =
          opt.disabled && opt.disabledReason
            ? `  (${opt.disabledReason})`
            : "";
        return (
          <box key={opt.id as unknown as string} flexDirection="column">
            <text fg={cursorColor}>
              {`${arrow} ${mark} ${opt.label}${note}`}
            </text>
            {opt.sub ? <text fg="#777777">{`      ${opt.sub}`}</text> : null}
          </box>
        );
      })}
      <text> </text>
      <text fg="#888888">
        ↑/↓ j/k move   space toggle   a all   enter confirm   q/esc abort
      </text>
      {DEBUG ? (
        <text fg="#F5A623">
          {`[debug] last="${lastKeyRef.current}" cursor=${cursor} checked={${[...checked].join(",")}}`}
        </text>
      ) : null}
    </box>
  );
}

export async function multiselect<T extends string>(
  opts: MultiselectOptions<T>,
): Promise<T[] | null> {
  const renderer = await createCliRenderer({ exitOnCtrlC: true });
  renderer.start();
  const root = createRoot(renderer);

  return await new Promise<T[] | null>((resolve) => {
    let finished = false;
    const finish = (result: T[] | null): void => {
      // Guard against the keypress handler firing finish twice (Enter
      // can produce both `return` and `enter` on some terminals; q/esc
      // similarly). React's reconciler does not tolerate a second
      // unmount commit on a torn-down container — symptom is
      // BindingError "Expected null or instance of Node" inside
      // commitBeforeMutationEffects → clearContainer.
      if (finished) return;
      finished = true;
      // Resolve first so the caller's `await` settles before teardown.
      // Defer unmount + destroy to the next microtask so React's
      // current commit cycle (the keypress that triggered finish)
      // finishes before the reconciler tries to mutate a container we
      // are about to clear.
      resolve(result);
      queueMicrotask(() => {
        try {
          root.unmount();
        } catch {
          // best-effort
        }
        try {
          renderer.destroy();
        } catch {
          // best-effort
        }
      });
    };

    root.render(
      <MultiselectApp
        title={opts.title}
        options={opts.options}
        onDone={finish}
      />,
    );
  });
}
