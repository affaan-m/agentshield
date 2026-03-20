export { startWatcher } from "./watcher.js";
export { createBaseline, diffBaseline, fingerprintFinding } from "./diff.js";
export { dispatchAlert, renderTerminalAlert, formatWebhookPayload, sendWebhookAlert } from "./alerts.js";
export type {
  WatchConfig,
  AlertMode,
  ScanBaseline,
  DriftResult,
  WatchEvent,
  WatcherState,
} from "./types.js";
