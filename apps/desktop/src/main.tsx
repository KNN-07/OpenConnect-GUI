// SPDX-License-Identifier: GPL-3.0-only
import {
  createContext,
  useContext,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createRoot } from "react-dom/client";
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import * as Dialog from "@radix-ui/react-dialog";
import * as Menu from "@radix-ui/react-dropdown-menu";
import {
  Plus,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  MoreHorizontal,
  X,
  Download,
  Upload,
  Activity,
  CircleAlert,
} from "lucide-react";
import type { Profile } from "../../../crates/model/bindings/Profile";
import type { ProfileDocument } from "../../../crates/model/bindings/ProfileDocument";
import type { SettingsRead } from "../../../crates/model/bindings/SettingsRead";
import type { SettingsDocument } from "../../../crates/model/bindings/SettingsDocument";
import type { Snapshot } from "../../../crates/model/bindings/Snapshot";
import type { LogRecord } from "../../../crates/model/bindings/LogRecord";
import type { DoctorReport } from "../../../crates/model/bindings/DoctorReport";
import type { LicenseText } from "../../../crates/model/bindings/LicenseText";
import type { AuthPrompt } from "../../../crates/model/bindings/AuthPrompt";
import type { CertificatePrompt } from "../../../crates/model/bindings/CertificatePrompt";
import type { BrowserPrompt } from "../../../crates/model/bindings/BrowserPrompt";
import type { Error as ClientError } from "../../../crates/model/bindings/Error";
import "./styles.css";

type ConnectEvent =
  | { type: "prompt"; data: AuthPrompt }
  | { type: "certificate"; data: CertificatePrompt }
  | { type: "browser"; data: BrowserPrompt }
  | { type: "browser_finished"; data: string }
  | { type: "snapshot" | "connected"; data: Snapshot }
  | { type: "notice" | "failed"; data: ClientError }
  | { type: "cancelled" };
type Observation =
  | { type: "snapshot"; data: Snapshot }
  | { type: "log"; data: LogRecord }
  | { type: "error"; data: ClientError };
type Interaction = Extract<
  ConnectEvent,
  { type: "prompt" | "certificate" | "browser" }
>;
type Modal =
  | { type: "editor"; profile: Profile; create: boolean }
  | { type: "settings" }
  | { type: "diagnostics" }
  | { type: "about" }
  | { type: "duplicate"; profile: Profile }
  | { type: "remove"; profile: Profile }
  | { type: "secrets"; profile: Profile }
  | { type: "switch"; profile: Profile }
  | null;
const errorOf = (value: unknown): ClientError =>
  typeof value === "object" &&
  value !== null &&
  "code" in value &&
  "message" in value
    ? (value as ClientError)
    : {
        code: "runtime_failure",
        message:
          "The desktop action failed. Retry, or open Diagnostics to check installation and service access.",
        details: null,
      };
const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
      ? `${(n / 1024).toFixed(1)} KiB`
      : `${(n / 1048576).toFixed(1)} MiB`;
const label = (s: string) => s.replaceAll("_", " ");
const DialogError = createContext<ClientError | null>(null);
function LicenseViewer() {
  const [records, setRecords] = useState<LicenseText[] | null>(null),
    [error, setError] = useState<ClientError | null>(null);
  const load = useCallback(async () => {
    setError(null);
    try {
      setRecords(await invoke<LicenseText[]>("licenses"));
    } catch (e) {
      setError(errorOf(e));
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <section>
      <h3>Installed license inventory</h3>
      {error ? (
        <p role="alert">
          {error.message} Repair the installed package and retry.
        </p>
      ) : records === null ? (
        <p>Reading the installed inventory…</p>
      ) : records.length === 0 ? (
        <p>No license inventory is installed. Repair the package.</p>
      ) : (
        records.map((record) => (
          <details key={record.name}>
            <summary>{record.name}</summary>
            <pre>{record.text}</pre>
          </details>
        ))
      )}
      <button onClick={() => void load()}>Reload license inventory</button>
    </section>
  );
}
function ModalFrame({
  title,
  children,
  close,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
}) {
  const previous = useRef(document.activeElement as HTMLElement | null);
  const error = useContext(DialogError);
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content
          className="modal"
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            previous.current?.focus();
          }}
          aria-describedby={undefined}
        >
          <div className="modal-heading">
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button aria-label="Close dialog">
                <X size={18} />
              </button>
            </Dialog.Close>
          </div>
          {error && (
            <section className="alert" role="alert">
              <div>
                <strong>{error.message}</strong>
                <p>{error.details}</p>
                <code>{error.code}</code>
                <p>
                  Correct the input and retry, or close this dialog and reload
                  for stale changes.
                </p>
              </div>
            </section>
          )}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
function App() {
  const [profiles, setProfiles] = useState<Profile[]>([]),
    [selected, setSelected] = useState<string | null>(null),
    [filter, setFilter] = useState("");
  const [settings, setSettings] = useState<SettingsRead | null>(null),
    [report, setReport] = useState<DoctorReport | null>(null),
    [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [serviceError, setServiceError] = useState<ClientError | null>(null),
    [error, setError] = useState<ClientError | null>(null),
    [loading, setLoading] = useState(true);
  const [modal, setModalState] = useState<Modal>(null),
    [interaction, setInteraction] = useState<Interaction | null>(null),
    [operation, setOperation] = useState<string | null>(null),
    [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<"details" | "logs">("details"),
    [logs, setLogs] = useState<LogRecord[]>([]),
    [logFilter, setLogFilter] = useState(""),
    [paused, setPaused] = useState(false),
    [frozen, setFrozen] = useState<LogRecord[]>([]);
  const [now, setNow] = useState(Date.now()),
    [rates, setRates] = useState<number[]>([]);
  const sample = useRef<{
      session: string | null;
      time: number;
      bytes: number;
    } | null>(null),
    latest = useRef<Snapshot | null>(null),
    opRef = useRef<string | null>(null),
    search = useRef<HTMLInputElement>(null);
  const setModal = (next: Modal) => {
    setError(null);
    setModalState(next);
  };
  const run = async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    try {
      return await action();
    } catch (e) {
      setError(errorOf(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  const reload = useCallback(async () => {
    const [p, s] = await Promise.all([
      invoke<ProfileDocument>("profiles"),
      invoke<SettingsRead>("read_settings"),
    ]);
    setProfiles(p.profiles);
    setSettings(s);
    setSelected((id) =>
      p.profiles.some((p) => p.id === id) ? id : (p.profiles[0]?.id ?? null),
    );
  }, []);
  const acceptSnapshot = useCallback((value: Snapshot) => {
    const old = latest.current;
    if (
      old &&
      old.service_instance_id === value.service_instance_id &&
      old.sequence > value.sequence
    )
      return;
    latest.current = value;
    setSnapshot(value);
    setServiceError(null);
    if (
      !old ||
      old.service_instance_id !== value.service_instance_id ||
      old.session_id !== value.session_id
    ) {
      sample.current = null;
      setRates([]);
      setLogs([]);
    }
  }, []);
  const observe = useCallback(async () => {
    const unavailable = (error: ClientError) => {
      setServiceError(error);
      setSnapshot(null);
      latest.current = null;
      sample.current = null;
      setRates([]);
    };
    const channel = new Channel<Observation>();
    channel.onmessage = (e) => {
      if (e.type === "snapshot") acceptSnapshot(e.data);
      else if (e.type === "log")
        setLogs((old) => [...old, e.data].slice(-2000));
      else unavailable(e.data);
    };
    try {
      await invoke("observe", { channel });
    } catch (e) {
      unavailable(errorOf(e));
    }
  }, [acceptSnapshot]);
  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      await reload();
    } catch (e) {
      setError(errorOf(e));
    }
    try {
      setReport(await invoke<DoctorReport>("doctor"));
    } catch (e) {
      setError(errorOf(e));
    }
    await observe();
    setLoading(false);
  }, [reload, observe]);
  useEffect(() => {
    if (!isTauri()) return;
    const focused = () => {
      void reload().catch((e) => setError(errorOf(e)));
    };
    window.addEventListener("focus", focused);
    return () => window.removeEventListener("focus", focused);
  }, [reload]);
  useEffect(() => {
    if (!isTauri()) {
      setLoading(false);
      setError({
        code: "service_unavailable",
        message:
          "Open the installed desktop application. Browser preview has no native service, keyring or file access.",
        details: null,
      });
      return;
    }
    void refresh();
  }, [refresh]);
  useEffect(() => {
    document.documentElement.dataset.theme =
      settings?.document.settings.theme ?? "system";
  }, [settings]);
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
      const s = latest.current;
      if (!s?.session_id) return;
      const time = performance.now(),
        total = s.traffic.rx_bytes + s.traffic.tx_bytes,
        old = sample.current;
      if (old && old.session === s.session_id && total >= old.bytes)
        setRates((values) =>
          [...values, ((total - old.bytes) * 1000) / (time - old.time)].slice(
            -60,
          ),
        );
      sample.current = { session: s.session_id, time, bytes: total };
    }, 1000);
    return () => clearInterval(timer);
  }, []);
  const newProfile = async () => {
    const profile = await invoke<Profile>("new_profile");
    setModal({
      type: "editor",
      profile: { ...profile, server: "" },
      create: true,
    });
  };
  const start = async (
    profile: Profile,
    secrets: Record<string, string> = {},
  ) => {
    setError(null);
    const operation = crypto.randomUUID();
    opRef.current = operation;
    setOperation(operation);
    setInteraction(null);
    const channel = new Channel<ConnectEvent>();
    channel.onmessage = (e) => {
      if (opRef.current !== operation) return;
      if (
        e.type === "prompt" ||
        e.type === "certificate" ||
        e.type === "browser"
      )
        setInteraction(e);
      else if (e.type === "browser_finished")
        setInteraction((old) =>
          old?.type === "browser" && old.data.transaction_id === e.data
            ? null
            : old,
        );
      else if (e.type === "snapshot" || e.type === "connected") {
        acceptSnapshot(e.data);
        if (e.type === "connected") {
          setInteraction(null);
          setOperation(null);
          opRef.current = null;
        }
      } else if (e.type === "notice") setError(e.data);
      else if (e.type === "failed" || e.type === "cancelled") {
        if (e.type === "failed") setError(e.data);
        setInteraction(null);
        setOperation(null);
        opRef.current = null;
        void observe();
      }
    };
    const rememberOther = secrets._remember === "yes";
    delete secrets._remember;
    try {
      await invoke("begin_connection", {
        id: profile.id,
        operation,
        secrets,
        rememberOther,
        channel,
      });
    } catch (e) {
      setOperation(null);
      opRef.current = null;
      throw e;
    }
  };
  const requestConnect = (profile: Profile) => {
    if (
      snapshot?.profile_id &&
      snapshot.state !== "disconnected" &&
      snapshot.state !== "failed" &&
      snapshot.state !== "authentication_required"
    ) {
      setModal({ type: "switch", profile });
      return;
    }
    setModal({ type: "secrets", profile });
  };
  const trayConnect = useRef<(id: string) => void>(() => {});
  trayConnect.current = (id) => {
    const p = profiles.find((p) => p.id === id);
    if (p) {
      setSelected(p.id);
      requestConnect(p);
    }
  };
  const cancel = async () => {
    const operation = opRef.current;
    if (operation) {
      await invoke("cancel_connection", { operation });
      setInteraction(null);
      setOperation(null);
      opRef.current = null;
      await observe();
    }
  };
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        search.current?.focus();
      }
      if (
        (e.ctrlKey || e.metaKey) &&
        e.key.toLowerCase() === "n" &&
        !modal &&
        !interaction
      ) {
        e.preventDefault();
        void run(newProfile);
      }
      if (e.key === "Escape" && !modal && operation) {
        void run(cancel);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  });
  useEffect(() => {
    if (!isTauri()) return;
    const a = listen<string>("tray-connect", (e) =>
        trayConnect.current(e.payload),
      ),
      b = listen<ClientError>("desktop-error", (e) => setError(e.payload));
    return () => {
      void a.then((f) => f());
      void b.then((f) => f());
    };
  }, []);
  useEffect(() => {
    const view = document.querySelector<HTMLDivElement>(".logs");
    if (view && !paused) view.scrollTop = view.scrollHeight;
  }, [logs, paused, tab]);
  useEffect(() => {
    const navigate = (event: KeyboardEvent) => {
      if (
        !(event.target instanceof HTMLButtonElement) ||
        event.target.getAttribute("role") !== "tab"
      )
        return;
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key))
        return;
      event.preventDefault();
      setTab(
        event.key === "Home"
          ? "details"
          : event.key === "End"
            ? "logs"
            : tab === "details"
              ? "logs"
              : "details",
      );
      requestAnimationFrame(() =>
        document
          .querySelector<HTMLButtonElement>(
            '[role="tab"][aria-selected="true"]',
          )
          ?.focus(),
      );
    };
    window.addEventListener("keydown", navigate);
    return () => window.removeEventListener("keydown", navigate);
  }, [tab]);
  const profile = profiles.find((p) => p.id === selected),
    caps = report?.capabilities;
  const connected =
    snapshot?.state === "connected" || snapshot?.state === "reconnecting";
  const active =
    !!snapshot &&
    (connected ||
      snapshot.state === "authenticating" ||
      snapshot.state === "connecting" ||
      snapshot.state === "disconnecting");
  const setupRequired =
    !!report &&
    (!!report.engine_error ||
      !!report.driver_error ||
      !report.service?.running ||
      report.service.approval_required);
  const state = serviceError
    ? "Service unavailable"
    : snapshot
      ? label(snapshot.state)
      : loading
        ? "Checking service"
        : "State unknown";
  const visibleLogs = (paused ? frozen : logs).filter((r) =>
    `${r.level} ${r.message}`.toLowerCase().includes(logFilter.toLowerCase()),
  );
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img
            src={new URL("./mark.svg?no-inline", import.meta.url).href}
            alt=""
          />
          <div>
            OpenConnect<span>GUI</span>
          </div>
        </div>
        <label className="search">
          <Search size={16} />
          <input
            ref={search}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search profiles"
            aria-label="Search profiles"
          />
        </label>
        <div className="sidebar-heading">
          <span>PROFILES</span>
          <button aria-label="Add profile" onClick={() => void run(newProfile)}>
            <Plus size={18} />
          </button>
        </div>
        <nav className="profile-list" aria-label="VPN profiles">
          {profiles
            .filter((p) =>
              `${p.name} ${p.protocol}`
                .toLowerCase()
                .includes(filter.toLowerCase()),
            )
            .map((p) => (
              <button
                key={p.id}
                className={selected === p.id ? "profile selected" : "profile"}
                onClick={() => setSelected(p.id)}
                aria-current={selected === p.id ? "page" : undefined}
              >
                <ShieldCheck size={18} />
                <span>
                  <strong>{p.name}</strong>
                  <small>
                    {caps?.protocols.find((x) => x.id === p.protocol)?.label ??
                      p.protocol}
                  </small>
                </span>
                {active && snapshot?.profile_id === p.id && (
                  <span className="active-dot" aria-label="Current session" />
                )}
              </button>
            ))}
          {filter &&
            !profiles.some((p) =>
              `${p.name} ${p.protocol}`
                .toLowerCase()
                .includes(filter.toLowerCase()),
            ) && <p className="muted">No matching profiles.</p>}
        </nav>
        <button
          onClick={() =>
            void run(async () => {
              await invoke("import_profiles");
              await reload();
            })
          }
        >
          <Upload size={16} />
          Import profiles
        </button>
        <footer>
          <button onClick={() => setModal({ type: "settings" })}>
            <SettingsIcon size={17} />
            Settings
          </button>
          <button onClick={() => setModal({ type: "diagnostics" })}>
            <Activity size={17} />
            Diagnostics
          </button>
          <small>Open source. No subscriptions.</small>
        </footer>
      </aside>
      <main>
        <header className="page-header">
          <div>
            <h1>{profile?.name ?? "VPN profiles"}</h1>
            <p>
              {profile?.server ??
                "Manage connections shared with the CLI and TUI."}
            </p>
          </div>
          {profile && (
            <Menu.Root>
              <Menu.Trigger asChild>
                <button aria-label="Profile actions">
                  <MoreHorizontal />
                </button>
              </Menu.Trigger>
              <Menu.Portal>
                <Menu.Content className="menu" sideOffset={8}>
                  {[
                    [
                      "Edit",
                      () =>
                        setModal({ type: "editor", profile, create: false }),
                    ],
                    [
                      "Duplicate",
                      () => setModal({ type: "duplicate", profile }),
                    ],
                    [
                      "Export",
                      () =>
                        void run(() =>
                          invoke("export_profiles", { id: profile.id }),
                        ),
                    ],
                    ["Remove", () => setModal({ type: "remove", profile })],
                  ].map(([text, action]) => (
                    <Menu.Item
                      key={text as string}
                      onSelect={action as () => void}
                    >
                      {text as string}
                    </Menu.Item>
                  ))}
                </Menu.Content>
              </Menu.Portal>
            </Menu.Root>
          )}
        </header>
        {(error || (!setupRequired && serviceError)) && (
          <section className="alert" role="alert">
            <CircleAlert size={20} />
            <div>
              <strong>{(error ?? serviceError)?.message}</strong>
              <p>{(error ?? serviceError)?.details}</p>
              <code>{(error ?? serviceError)?.code}</code>
              <div className="actions">
                <button onClick={() => void run(refresh)}>
                  Retry / reload
                </button>
                <button onClick={() => setModal({ type: "diagnostics" })}>
                  Open diagnostics
                </button>
                {error && (
                  <button onClick={() => setError(null)}>Dismiss</button>
                )}
              </div>
            </div>
          </section>
        )}
        {settings?.auto_connect_error && (
          <section className="alert">
            <p>{settings.auto_connect_error.message}</p>
            <button onClick={() => setModal({ type: "settings" })}>
              Choose auto-connect profile
            </button>
          </section>
        )}
        {setupRequired && (
          <section className="alert" role="alert">
            <CircleAlert size={20} />
            <div>
              <strong>Finish setting up OpenConnect GUI</strong>
              <p>
                {report?.engine_error?.message ??
                  report?.driver_error?.message ??
                  report?.service_error?.message ??
                  (report?.service?.approval_required
                    ? "Approve the tunnel service in system settings."
                    : report?.service?.registered
                      ? "The system tunnel service is not running."
                      : "The system tunnel service is not registered.")}
              </p>
              <button onClick={() => setModal({ type: "diagnostics" })}>
                Review dependencies and install / repair
              </button>
            </div>
          </section>
        )}
        {(profile || active || operation) && (
          <section className="connection card">
            <div className="status-line">
              <span className={`status-icon ${connected ? "online" : ""}`}>
                <ShieldCheck size={28} />
              </span>
              <div>
                <span className="status-pill" role="status">
                  {state}
                </span>
                <p>
                  {snapshot?.profile_name
                    ? `Service session: ${snapshot.profile_name}`
                    : "The system service owns your tunnel, independently of this window."}
                </p>
              </div>
            </div>
            <div className="actions">
              {operation ? (
                <button className="primary" onClick={() => void run(cancel)}>
                  Cancel connection
                </button>
              ) : connected ? (
                <button
                  className="primary"
                  onClick={() => void run(() => invoke("disconnect"))}
                >
                  Disconnect
                </button>
              ) : (
                <button
                  className="primary"
                  disabled={!profile || !caps || !snapshot || busy}
                  onClick={() => profile && requestConnect(profile)}
                >
                  Connect
                </button>
              )}
              {connected && profile && snapshot?.profile_id !== profile.id && (
                <button onClick={() => requestConnect(profile)}>
                  Switch to selected profile
                </button>
              )}
            </div>
            {snapshot?.last_error && (
              <p className="error-text">{snapshot.last_error.message}</p>
            )}
            <div className="stats">
              <div>
                <span>Duration</span>
                <strong>
                  {snapshot?.started_at && connected
                    ? `${Math.floor(
                        Math.max(0, now / 1000 - snapshot.started_at) / 3600,
                      )
                        .toString()
                        .padStart(2, "0")}:${Math.floor(
                        (Math.max(0, now / 1000 - snapshot.started_at) / 60) %
                          60,
                      )
                        .toString()
                        .padStart(2, "0")}:${Math.floor(
                        Math.max(0, now / 1000 - snapshot.started_at) % 60,
                      )
                        .toString()
                        .padStart(2, "0")}`
                    : "—"}
                </strong>
              </div>
              <div>
                <span>Address</span>
                <strong>
                  {snapshot?.network?.addresses.join(", ") || "—"}
                </strong>
              </div>
              <div>
                <span>Transport</span>
                <strong>{snapshot?.network?.transport || "—"}</strong>
              </div>
              <div>
                <span>Received / sent</span>
                <strong>
                  {snapshot
                    ? `${bytes(snapshot.traffic.rx_bytes)} / ${bytes(snapshot.traffic.tx_bytes)}`
                    : "—"}
                </strong>
              </div>
            </div>
            <div className="traffic">
              <span>
                {rates.length
                  ? `${bytes(rates.at(-1) ?? 0)}/s`
                  : "Waiting for traffic samples"}
              </span>
              <svg
                viewBox="0 0 300 36"
                role="img"
                aria-label="Combined transfer rate, last 60 seconds"
              >
                <polyline
                  points={rates
                    .map(
                      (v, i) =>
                        `${(i * 300) / 59},${34 - (v / Math.max(1, ...rates)) * 30}`,
                    )
                    .join(" ")}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                />
              </svg>
            </div>
          </section>
        )}
        {!profile && !loading ? (
          <section className="empty card">
            <ShieldCheck size={40} />
            <h2>Add your first VPN</h2>
            <p>
              Your profiles are shared with the CLI and TUI. Credentials stay in
              your operating system keyring only when you opt in.
            </p>
            <div className="actions">
              <button className="primary" onClick={() => void run(newProfile)}>
                <Plus size={16} />
                Add profile
              </button>
              <button
                onClick={() =>
                  void run(async () => {
                    await invoke("import_profiles");
                    await reload();
                  })
                }
              >
                Import JSON
              </button>
            </div>
          </section>
        ) : (
          <section className="card workspace">
            <div
              className="tabs"
              role="tablist"
              aria-label="Connection information"
            >
              {(["details", "logs"] as const).map((t) => (
                <button
                  key={t}
                  role="tab"
                  aria-selected={tab === t}
                  onClick={() => setTab(t)}
                >
                  {label(t)}
                </button>
              ))}
            </div>
            {tab === "details" ? (
              <div role="tabpanel">
                <dl className="details">
                  <dt>Profile protocol</dt>
                  <dd>{profile?.protocol ?? "—"}</dd>
                  <dt>Interface</dt>
                  <dd>{snapshot?.network?.interface ?? "—"}</dd>
                  <dt>DNS servers</dt>
                  <dd>{snapshot?.network?.dns_servers.join(", ") || "—"}</dd>
                  <dt>Search domains</dt>
                  <dd>{snapshot?.network?.search_domains.join(", ") || "—"}</dd>
                  <dt>Session ID</dt>
                  <dd>{snapshot?.session_id ?? "—"}</dd>
                  <dt>Routes</dt>
                  <dd>
                    {snapshot?.network?.routes.map((r) => (
                      <div key={r}>{r}</div>
                    )) ?? "—"}
                  </dd>
                </dl>
                <p className="muted">
                  Negotiated network settings are read-only. Changing the
                  selected profile does not change an active tunnel.
                </p>
              </div>
            ) : (
              <div role="tabpanel">
                <div className="log-tools">
                  <input
                    aria-label="Search logs"
                    placeholder="Search redacted logs"
                    value={logFilter}
                    onChange={(e) => setLogFilter(e.target.value)}
                  />
                  <button
                    aria-pressed={paused}
                    onClick={() => {
                      if (!paused) setFrozen(logs);
                      setPaused(!paused);
                    }}
                  >
                    {paused ? "Resume" : "Pause"}
                  </button>
                  <button
                    onClick={() => {
                      setLogs([]);
                      setFrozen([]);
                    }}
                  >
                    Clear view
                  </button>
                  <button
                    onClick={() => void run(() => invoke("export_diagnostics"))}
                  >
                    <Download size={16} />
                    Export
                  </button>
                </div>
                <div className="logs" aria-live={paused ? "off" : "polite"}>
                  {visibleLogs.map((r, i) => (
                    <div key={`${r.timestamp}-${i}`}>
                      <time>
                        {new Date(r.timestamp * 1000).toLocaleTimeString()}
                      </time>
                      <span>{r.level}</span>
                      <p>{r.message}</p>
                    </div>
                  ))}
                  {!visibleLogs.length && (
                    <p>No matching service logs. Nothing is simulated.</p>
                  )}
                </div>
                <small className="muted">
                  Up to 2,000 redacted records. Clear removes this view, not
                  service history.
                </small>
              </div>
            )}
          </section>
        )}
        <p className="privacy">
          Closing this window leaves an established tunnel running.{" "}
          <button
            className="link"
            onClick={() =>
              void run(() => invoke("quit_ui", { disconnectFirst: false }))
            }
          >
            Quit UI
          </button>
          <button
            className="link"
            onClick={() =>
              void run(() => invoke("quit_ui", { disconnectFirst: true }))
            }
          >
            Disconnect and quit
          </button>
        </p>
      </main>
      <DialogError.Provider value={error}>
        {modal && (
          <ModalFrame
            title={
              modal.type === "editor"
                ? modal.create
                  ? "New profile"
                  : "Edit profile"
                : modal.type === "secrets"
                  ? "Connection credentials"
                  : label(modal.type)
            }
            close={() => setModal(null)}
          >
            {modal.type === "editor" && (
              <ProfileEditor
                initial={modal.profile}
                report={report}
                save={async (p) => {
                  await invoke("save_profile", {
                    profile: p,
                    create: modal.create,
                  });
                  await reload();
                  setModal(null);
                }}
                fail={(e) => setError(errorOf(e))}
              />
            )}
            {modal.type === "settings" && settings && (
              <SettingsEditor
                initial={settings.document}
                profiles={profiles}
                save={async (document) => {
                  const saved = await invoke<SettingsDocument>(
                    "save_settings",
                    {
                      settings: document.settings,
                      revision: document.revision,
                    },
                  );
                  setSettings({ ...settings, document: saved });
                  setModal(null);
                }}
                fail={(e) => setError(errorOf(e))}
                forget={(id) => run(() => invoke("forget_credentials", { id }))}
                about={() => setModal({ type: "about" })}
              />
            )}
            {modal.type === "settings" && !settings && (
              <p>
                Settings could not be loaded. Close this dialog and choose Retry
                / reload.
              </p>
            )}
            {modal.type === "diagnostics" && (
              <button
                onClick={() =>
                  void run(() => invoke("export_profiles", { id: null }))
                }
              >
                Export all profile metadata
              </button>
            )}
            {modal.type === "diagnostics" && (
              <>
                <div className="actions">
                  <button
                    onClick={() =>
                      void run(async () => setReport(await invoke("doctor")))
                    }
                  >
                    Refresh checks
                  </button>
                  <button
                    onClick={() => void run(() => invoke("export_diagnostics"))}
                  >
                    Export diagnostics
                  </button>
                </div>
                <dl className="details">
                  <dt>Engine</dt>
                  <dd>
                    {report?.capabilities?.engine_version ??
                      report?.engine_error?.message ??
                      "Not checked"}
                  </dd>
                  <dt>Native API</dt>
                  <dd>{caps ? `${caps.api_major}.${caps.api_minor}` : "—"}</dd>
                  <dt>Service</dt>
                  <dd>
                    {report?.service
                      ? `Packaged: ${report.service.packaged}; registered: ${report.service.registered}; running: ${report.service.running}`
                      : (report?.service_error?.message ?? "Not checked")}
                  </dd>
                  <dt>Driver</dt>
                  <dd>
                    {report?.driver_ready
                      ? "Ready"
                      : (report?.driver_error?.message ?? "Not ready")}
                  </dd>
                </dl>
                <div className="actions">
                  {(["install", "repair", "uninstall"] as const).map(
                    (action) => (
                      <button
                        key={action}
                        onClick={() =>
                          void run(async () => {
                            await invoke("manage_service", { action });
                            await refresh();
                          })
                        }
                      >
                        {label(action)} service
                      </button>
                    ),
                  )}
                  {report?.service?.approval_required && (
                    <button
                      onClick={() =>
                        void run(() => invoke("approval_settings"))
                      }
                    >
                      Open Login Items approval
                    </button>
                  )}
                </div>
                <h3>Native protocols</h3>
                {caps?.protocols.map((p) => (
                  <p key={p.id}>
                    <strong>{p.label}</strong> · {p.id}
                    <br />
                    {p.description}
                  </p>
                ))}
                <h3>Authentication capabilities</h3>
                {caps &&
                  (
                    [
                      "pkcs11",
                      "totp",
                      "hotp",
                      "stoken",
                      "yubioath",
                      "hpke",
                    ] as const
                  ).map((k) => (
                    <p key={k}>
                      {k.toUpperCase()}:{" "}
                      {caps[k]
                        ? "Available"
                        : "Not included in this native build"}
                    </p>
                  ))}
                <p>
                  External browsers use their own trust store. Provision
                  organization CAs through normal OS/browser administration.
                  Strict certificate pins cannot be enforced by embedded
                  webviews; choose an explicit system/manual alternative.
                </p>
              </>
            )}
            {modal.type === "about" && (
              <>
                <h3>OpenConnect GUI 0.1.0</h3>
                <p>
                  A local, open-source client. No telemetry, cloud backend,
                  activation or subscriptions.
                </p>
                <p>
                  Original application code and artwork: GPL-3.0-only.
                  OpenConnect: LGPL-2.1-only; the combined bridge library is
                  GPL-3.0-only. Bundled Unix vpnc-script: GPL-2.0-or-later.
                  Windows Wintun includes its upstream redistribution license.
                </p>
                <p>
                  Tauri, React, Radix, Lucide and native dependency licenses are
                  included with the installed source/license inventory. Source
                  and release recipes are distributed with the application.
                </p>
              </>
            )}
            {modal.type === "about" && <LicenseViewer />}
            {modal.type === "duplicate" && (
              <SimpleForm
                label="New unique profile name"
                submit={async (name) => {
                  await invoke("duplicate_profile", {
                    id: modal.profile.id,
                    name,
                  });
                  await reload();
                  setModal(null);
                }}
                fail={(e) => setError(errorOf(e))}
              />
            )}
            {modal.type === "remove" && (
              <>
                <p>
                  Remove “{modal.profile.name}” and its saved credentials?
                  Active or pending profiles cannot be removed.
                </p>
                <button
                  className="danger"
                  onClick={() =>
                    void run(async () => {
                      await invoke("remove_profile", {
                        id: modal.profile.id,
                        revision: modal.profile.revision,
                      });
                      await reload();
                      setModal(null);
                    })
                  }
                >
                  Remove profile
                </button>
              </>
            )}
            {modal.type === "switch" && (
              <>
                <p>
                  A session already owns the machine-wide tunnel. Disconnect it
                  before connecting “{modal.profile.name}”?
                </p>
                <button
                  onClick={() =>
                    void run(async () => {
                      await invoke("disconnect");
                      await observe();
                      setModal({ type: "secrets", profile: modal.profile });
                    })
                  }
                >
                  Disconnect, then continue
                </button>
              </>
            )}
            {modal.type === "secrets" && (
              <SecretForm
                profile={modal.profile}
                submit={async (secrets) => {
                  setModal(null);
                  await start(modal.profile, secrets);
                }}
                fail={(e) => setError(errorOf(e))}
              />
            )}
          </ModalFrame>
        )}
        {interaction && operation && (
          <ModalFrame
            title={
              interaction.type === "prompt"
                ? "Authentication"
                : interaction.type === "certificate"
                  ? "Verify server certificate"
                  : "Browser authentication"
            }
            close={() => void run(cancel)}
          >
            {interaction.type === "prompt" ? (
              <AuthForm
                key={interaction.data.prompt_id}
                prompt={interaction.data}
                submit={async (answers) => {
                  await invoke("auth_reply", {
                    operation,
                    attemptId: interaction.data.attempt_id,
                    promptId: interaction.data.prompt_id,
                    answers,
                  });
                  setInteraction((old) => (old === interaction ? null : old));
                }}
                fail={(e) => setError(errorOf(e))}
              />
            ) : interaction.type === "certificate" ? (
              <>
                <p>
                  {interaction.data.host}:{interaction.data.port}
                </p>
                <p className="error-text">
                  {interaction.data.changed_pin
                    ? "The saved certificate has changed. "
                    : ""}
                  {interaction.data.reason}
                </p>
                <pre>{interaction.data.details}</pre>
                <code className="fingerprint">
                  {interaction.data.fingerprint}
                </code>
                <div className="actions">
                  {(["reject", "accept_attempt", "pin"] as const).map(
                    (decision) => (
                      <button
                        key={decision}
                        onClick={() =>
                          void run(async () => {
                            await invoke("certificate_reply", {
                              operation,
                              promptId: interaction.data.prompt_id,
                              decision,
                            });
                            setInteraction((old) =>
                              old === interaction ? null : old,
                            );
                          })
                        }
                      >
                        {decision === "pin"
                          ? "Pin this exact host + port"
                          : label(decision)}
                      </button>
                    ),
                  )}
                </div>
              </>
            ) : (
              <>
                <p>Expected VPN: {interaction.data.expected_origin}</p>
                <p>
                  {label(interaction.data.phase)} ·{" "}
                  {label(interaction.data.stage)}
                </p>
                {interaction.data.stage === "confirm_account" ? (
                  <>
                    <p>
                      Continue as <strong>{interaction.data.account}</strong>?
                      Confirm only if this is the account you just
                      authenticated.
                    </p>
                    <div className="actions">
                      {[false, true].map((accepted) => (
                        <button
                          key={String(accepted)}
                          onClick={() =>
                            void run(async () => {
                              await invoke("browser_reply", {
                                operation,
                                transactionId: interaction.data.transaction_id,
                                accepted,
                              });
                              setInteraction((old) =>
                                old === interaction ? null : old,
                              );
                            })
                          }
                        >
                          {accepted ? "Confirm account" : "Reject"}
                        </button>
                      ))}
                    </div>
                  </>
                ) : (
                  <>
                    <p>
                      Complete the sign-in in your browser. Closing this dialog
                      cancels the attempt.
                    </p>
                    {interaction.data.stage === "manual_input" && (
                      <>
                        <p>
                          Copy the private URL, authenticate, then copy the
                          callback and paste it directly into the native broker.
                          The app page never reads either value. Clipboard
                          history and OS custom-URL dispatch may expose
                          credentials; clear clipboard history afterward.
                        </p>
                        <div className="actions">
                          <button
                            onClick={() =>
                              void run(() =>
                                invoke("browser_clipboard", {
                                  operation,
                                  transactionId:
                                    interaction.data.transaction_id,
                                  paste: false,
                                }),
                              )
                            }
                          >
                            Copy private sign-in URL
                          </button>
                          <button
                            onClick={() =>
                              void run(() =>
                                invoke("browser_clipboard", {
                                  operation,
                                  transactionId:
                                    interaction.data.transaction_id,
                                  paste: true,
                                }),
                              )
                            }
                          >
                            Submit callback from clipboard
                          </button>
                        </div>
                      </>
                    )}
                  </>
                )}
              </>
            )}
          </ModalFrame>
        )}
      </DialogError.Provider>
    </div>
  );
}

function SimpleForm({
  label: caption,
  submit,
  fail,
}: {
  label: string;
  submit: (text: string) => Promise<void>;
  fail: (e: unknown) => void;
}) {
  const [text, setText] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        void submit(text)
          .catch(fail)
          .finally(() => setBusy(false));
      }}
    >
      <label>
        {caption}
        <input
          required
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      <button className="primary" disabled={busy}>
        Save
      </button>
    </form>
  );
}
function AuthForm({
  prompt,
  submit,
  fail,
}: {
  prompt: AuthPrompt;
  submit: (answers: Record<string, string>) => Promise<void>;
  fail: (e: unknown) => void;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const form = e.currentTarget,
          answers = Object.fromEntries(new FormData(form).entries()) as Record<
            string,
            string
          >;
        setBusy(true);
        void submit(answers)
          .catch(fail)
          .finally(() => {
            form.reset();
            Object.keys(answers).forEach((k) => (answers[k] = ""));
            setBusy(false);
          });
      }}
    >
      {[prompt.banner, prompt.message, prompt.error]
        .filter(Boolean)
        .map((t, i) => (
          <p key={i}>{t}</p>
        ))}
      {prompt.fields.map((f) => (
        <label key={f.name}>
          {f.label}
          {f.kind === "select" ? (
            <select name={f.name} required={f.required} defaultValue="">
              <option value="" disabled>
                Select a choice
              </option>
              {f.choices.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label} ({c.id})
                </option>
              ))}
            </select>
          ) : f.kind === "sso_token" || f.kind === "sso_user" ? (
            <p>
              Complete this field through the browser authentication window.
            </p>
          ) : (
            <input
              name={f.name}
              required={f.required}
              type={
                f.kind === "password" || f.kind === "token"
                  ? "password"
                  : "text"
              }
              inputMode={f.numeric ? "numeric" : "text"}
              maxLength={65536}
              autoComplete="off"
            />
          )}
        </label>
      ))}
      <button className="primary" disabled={busy}>
        Continue
      </button>
      <p className="muted">
        Answers apply only to this authentication step. One-time codes are never
        saved.
      </p>
    </form>
  );
}
function SecretForm({
  profile,
  submit,
  fail,
}: {
  profile: Profile;
  submit: (secrets: Record<string, string>) => Promise<void>;
  fail: (e: unknown) => void;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        const form = e.currentTarget,
          secrets = Object.fromEntries(
            [...new FormData(form).entries()].filter(([, v]) => v !== ""),
          ) as Record<string, string>;
        void submit(secrets)
          .catch(fail)
          .finally(() => {
            form.reset();
            Object.keys(secrets).forEach((k) => (secrets[k] = ""));
            setBusy(false);
          });
      }}
    >
      <p>
        Leave saved values blank to use the OS keyring, or enter session-only
        values. The server may request additional MFA or certificate PINs.
      </p>
      {[
        ["password", "Primary password (never enter an OTP here)"],
        ...(profile.client_certificate
          ? [["key_passphrase", "Private key passphrase"]]
          : []),
        ...(profile.secondary_certificate
          ? [["secondary_key_passphrase", "Secondary key passphrase"]]
          : []),
        ...(profile.token_mode !== "none"
          ? [["token_seed", "Token secret (upstream format)"]]
          : []),
        ...(profile.proxy
          ? [["proxy_credentials", "Proxy credentials (username:password)"]]
          : []),
      ].map(([name, title]) => (
        <label key={name}>
          {title}
          <input
            name={name}
            type="password"
            autoComplete="off"
            maxLength={65536}
          />
        </label>
      ))}
      <label className="check">
        <input name="_remember" value="yes" type="checkbox" />
        Save supplied key passphrases, token secret and proxy credentials in the
        OS keyring
      </label>
      <p>
        {profile.remember_password
          ? "The primary password above replaces the saved password after successful authentication. Leave it blank to reuse the keyring."
          : "Primary password persistence is disabled for this profile."}{" "}
        Generic challenge answers and one-time codes are never captured for
        saving. If the keyring is locked or unavailable, uncheck saving to
        continue with session-only values.
      </p>
      <button className="primary" disabled={busy}>
        Connect
      </button>
    </form>
  );
}
function ProfileEditor({
  initial,
  report,
  save,
  fail,
}: {
  initial: Profile;
  report: DoctorReport | null;
  save: (p: Profile) => Promise<void>;
  fail: (e: unknown) => void;
}) {
  const [p, setP] = useState(initial),
    [section, setSection] = useState("General"),
    [busy, setBusy] = useState(false);
  const caps = report?.capabilities;
  const text = (key: keyof Profile, title: string, file = false) => (
    <label key={key}>
      {title}
      <div className="field-row">
        <input
          required={key === "name" || key === "server"}
          value={String(p[key] ?? "")}
          onChange={(e) =>
            setP({
              ...p,
              [key]:
                e.target.value ||
                (key === "name" || key === "server" ? "" : null),
            })
          }
        />
        {file && (
          <button
            type="button"
            onClick={() =>
              void invoke<string | null>("choose_certificate")
                .then((path) => {
                  if (path) setP((old) => ({ ...old, [key]: path }));
                })
                .catch(fail)
            }
          >
            Browse
          </button>
        )}
      </div>
    </label>
  );
  const check = (key: keyof Profile, title: string) => (
    <label className="check" key={key}>
      <input
        type="checkbox"
        checked={Boolean(p[key])}
        onChange={(e) => setP({ ...p, [key]: e.target.checked })}
      />
      {title}
    </label>
  );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        let server = p.server.trim();
        if (!server.includes("://")) server = `https://${server}`;
        void save({ ...p, server })
          .catch(fail)
          .finally(() => setBusy(false));
      }}
    >
      <div className="tabs">
        {["General", "Authentication", "Advanced"].map((s) => (
          <button
            type="button"
            key={s}
            aria-pressed={section === s}
            onClick={() => setSection(s)}
          >
            {s}
          </button>
        ))}
      </div>
      {section === "General" && (
        <>
          {text("name", "Profile name")}
          {text("server", "HTTPS server (path is preserved)")}
          <label>
            Protocol
            <select
              value={p.protocol}
              onChange={(e) => setP({ ...p, protocol: e.target.value })}
            >
              {!caps?.protocols.some((x) => x.id === p.protocol) && (
                <option value={p.protocol}>
                  {p.protocol} (not available in this engine)
                </option>
              )}
              {caps?.protocols.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.label}
                </option>
              ))}
            </select>
          </label>
          {!caps && (
            <p className="muted">
              Install the native engine to discover supported protocols.
              Imported protocol IDs are preserved, never remapped.
            </p>
          )}
          {p.protocol === "gp" && (
            <>
              {check("direct_gateway", "Connect directly to gateway")}
              {text("gateway", "Saved gateway (must still be offered)")}
            </>
          )}
          {text("auth_group", "Authentication group")}
        </>
      )}
      {section === "Authentication" && (
        <>
          {text("username", "Username")}
          {check(
            "remember_password",
            "Remember password in the OS keyring (explicit opt-in)",
          )}
          <label>
            Browser mode
            <select
              value={p.browser_mode}
              onChange={(e) =>
                setP({
                  ...p,
                  browser_mode: e.target.value as Profile["browser_mode"],
                })
              }
            >
              {["auto", "system", "embedded", "manual"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label>
            Token mode
            <select
              value={p.token_mode}
              onChange={(e) =>
                setP({
                  ...p,
                  token_mode: e.target.value as Profile["token_mode"],
                })
              }
            >
              {(
                ["none", "totp", "hotp", "stoken", "yubioath", "oidc"] as const
              ).map((v) => {
                const supported =
                  v === "none" || v === "oidc" || Boolean(caps?.[v]);
                return (
                  <option
                    key={v}
                    disabled={!supported && p.token_mode !== v}
                    value={v}
                  >
                    {v}
                    {supported ? "" : " — unavailable in this build"}
                  </option>
                );
              })}
            </select>
          </label>
          {text("ca_file", "Organization CA file", true)}
          {text(
            "client_certificate",
            "Client certificate path or supported URI",
            true,
          )}
          {text("client_key", "Private key path or supported URI", true)}
          {text("secondary_certificate", "Secondary certificate", true)}
          {text("secondary_key", "Secondary key", true)}
          {!caps?.pkcs11 && (
            <p className="muted">
              PKCS#11 is not available in the current engine. Hardware
              certificate URIs cannot connect until a capable runtime is
              installed.
            </p>
          )}
          <p className="muted">
            Private keys stay in this unprivileged process. Embedded browser
            authentication fails closed when strict pins cannot be enforced.
          </p>
        </>
      )}
      {section === "Advanced" && (
        <>
          {text("proxy", "Proxy URL (no password or userinfo)")}
          {text("user_agent", "User agent")}
          {text("sni", "TLS SNI hostname")}
          <label>
            Reported OS
            <select
              value={p.reported_os ?? ""}
              onChange={(e) =>
                setP({ ...p, reported_os: e.target.value || null })
              }
            >
              {[
                "",
                "linux",
                "linux-64",
                "win",
                "mac-intel",
                "android",
                "apple-ios",
              ].map((v) => (
                <option key={v} value={v}>
                  {v || "Native default"}
                </option>
              ))}
            </select>
          </label>
          <label>
            MTU
            <input
              type="number"
              min={p.disable_ipv6 ? 576 : 1280}
              max={9000}
              value={p.mtu ?? ""}
              onChange={(e) =>
                setP({
                  ...p,
                  mtu: e.target.value ? Number(e.target.value) : null,
                })
              }
            />
          </label>
          <label>
            Reconnect timeout (seconds)
            <input
              type="number"
              min={0}
              max={4294967295}
              value={p.reconnect_timeout_secs}
              onChange={(e) =>
                setP({ ...p, reconnect_timeout_secs: Number(e.target.value) })
              }
            />
          </label>
          {check("disable_dtls", "Disable DTLS")}
          {check("disable_ipv6", "Disable IPv6")}
        </>
      )}
      <div className="form-footer">
        <small>Revision {p.revision} · metadata only</small>
        <button className="primary" disabled={busy}>
          Save profile
        </button>
      </div>
    </form>
  );
}
function SettingsEditor({
  initial,
  profiles,
  save,
  fail,
  forget,
  about,
}: {
  initial: SettingsDocument;
  profiles: Profile[];
  save: (s: SettingsDocument) => Promise<void>;
  fail: (e: unknown) => void;
  forget: (id: string) => Promise<unknown>;
  about: () => void;
}) {
  const [doc, setDoc] = useState(initial),
    [busy, setBusy] = useState(false);
  const s = doc.settings;
  const change = (patch: Partial<typeof s>) =>
    setDoc({ ...doc, settings: { ...s, ...patch } });
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        void save(doc)
          .catch(fail)
          .finally(() => setBusy(false));
      }}
    >
      <label>
        Appearance
        <select
          value={s.theme}
          onChange={(e) => change({ theme: e.target.value as typeof s.theme })}
        >
          {["system", "light", "dark"].map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={s.start_at_login}
          onChange={(e) => change({ start_at_login: e.target.checked })}
        />
        Start auto-connect at user login
      </label>
      <label>
        Auto-connect profile
        <select
          value={s.auto_connect_profile_id ?? ""}
          onChange={(e) =>
            change({ auto_connect_profile_id: e.target.value || null })
          }
        >
          <option value="">Disabled</option>
          {s.auto_connect_profile_id &&
            !profiles.some((p) => p.id === s.auto_connect_profile_id) && (
              <option value={s.auto_connect_profile_id}>
                Missing profile — auto-connect unavailable
              </option>
            )}
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <p>
        Login connections run unprivileged. If authentication needs interaction,
        open the app and connect; passwords are not repeatedly retried.
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={s.close_to_tray}
          onChange={(e) => change({ close_to_tray: e.target.checked })}
        />
        Close to tray when a system tray is available
      </label>
      <h3>Saved credentials</h3>
      {profiles.map((p) => (
        <div className="credential-row" key={p.id}>
          <span>{p.name}</span>
          <button type="button" onClick={() => void forget(p.id)}>
            Remove saved credentials
          </button>
        </div>
      ))}
      <div className="form-footer">
        <button type="button" onClick={about}>
          About / licenses
        </button>
        <button className="primary" disabled={busy}>
          Save settings
        </button>
      </div>
    </form>
  );
}
const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<App />);
