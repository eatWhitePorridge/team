export type PollInterval<T> = number | ((data: T | undefined) => number);
export interface PollClock {
  now: () => number;
  setTimeout: (callback: () => void, delay: number) => unknown;
  clearTimeout: (timer: unknown) => void;
}

const defaultClock: PollClock = {
  now: () => performance.now(),
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  clearTimeout: (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
};

// Read-only requests only. Scheduling is independent of React and the DOM.
export function createPoller<T>({ read, interval, onStart, onData, onError, visible = true, clock = defaultClock }: {
  read: (signal: AbortSignal) => Promise<T>;
  interval: PollInterval<T>;
  onStart?: (manual: boolean) => void;
  onData: (data: T) => void;
  onError: (error: unknown) => void;
  visible?: boolean;
  clock?: PollClock;
}) {
  const controller = new AbortController();
  let stopped = false;
  let running = false;
  let pendingRefresh = false;
  let timer: unknown;
  let lastStarted = -Infinity;
  let failures = 0;
  let latest: T | undefined;

  const clearTimer = () => {
    if (timer !== undefined) clock.clearTimeout(timer);
    timer = undefined;
  };
  const schedule = () => {
    if (stopped || running || !visible) return;
    clearTimer();
    const ms = typeof interval === 'function' ? interval(latest) : interval;
    if (!pendingRefresh && !(ms > 0)) return;
    // Normal cadence is start-to-start, not response time + interval. A slow
    // endpoint still has a quiet gap and never accumulates overlapping reads.
    const delay = pendingRefresh ? Math.max(0, 250 - (clock.now() - lastStarted))
      : failures ? Math.min(30_000, ms * 2 ** Math.min(failures, 5))
      : Math.max(250, ms - (clock.now() - lastStarted));
    timer = clock.setTimeout(() => { timer = undefined; void load(pendingRefresh); }, delay);
  };
  const load = async (manual: boolean) => {
    if (stopped || !visible) return;
    clearTimer();
    if (running) { pendingRefresh = true; return; }
    pendingRefresh = false;
    running = true;
    lastStarted = clock.now();
    try {
      onStart?.(manual);
      const data = await read(controller.signal);
      if (stopped) return;
      latest = data;
      failures = 0;
      onData(data);
    } catch (error) {
      if (!stopped) { failures += 1; onError(error); }
    } finally {
      running = false;
      schedule();
    }
  };
  const refresh = () => {
    if (stopped) return;
    clearTimer();
    if (running || !visible) { pendingRefresh = true; return; }
    void load(true);
  };
  return {
    refresh,
    setVisible(next: boolean) {
      if (stopped || visible === next) return;
      visible = next;
      if (visible) refresh();
      else clearTimer();
    },
    wake() {
      // visibilitychange + focus often arrive together; do not send two reads.
      if (visible && !running && clock.now() - lastStarted >= 1000) refresh();
    },
    stop() { stopped = true; clearTimer(); controller.abort(); },
  };
}
