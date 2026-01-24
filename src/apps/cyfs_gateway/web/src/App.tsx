import React, { useState, useEffect } from 'react';

// --- Icons (SVG Components) ---
const Icons = {
  Grid: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>,
  Server: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>,
  Network: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>,
  Activity: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>,
  Shield: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>,
  Database: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s 9-1.34 9-3V5"></path></svg>,
  Flask: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="10" y1="2" x2="14" y2="2"></line><line x1="12" y1="2" x2="12" y2="5"></line><path d="M8.5 2H15.5L20 22H4L8.5 2Z"></path><path d="M8.5 12H15.5"></path></svg>,
  Settings: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>,
  Code: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>,
  Menu: () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>,
  Gateway: () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14"></path><path d="M12 5v14"></path><rect x="2" y="2" width="20" height="20" rx="5" ry="5" style={{strokeDasharray: "4 4"}}></rect></svg>
};

// --- Views Components ---

const SimpleCard = ({ title, value, label }: { title: string; value: string; label: string }) => (
  <div className="card">
    <div className="text-muted text-sm uppercase tracking-wider">{title}</div>
    <div className="stat-value">{value}</div>
    <div className="stat-label">{label}</div>
  </div>
);

const MODULE_DESC = {
  tunnels: "Manage tunnel resources and verify link health.",
  rules: "Author Post rules, validate syntax, and apply in order.",
  databases: "Query and maintain subscription and custom databases.",
  tests: "Run predefined website tests and trace results.",
  config: "Inspect merged config, edit drafts, validate, and roll back.",
  settings: "System settings, UI mode, TLS MITM, and security access.",
};

const MOCK_TUNNELS = [
  { id: "rtcp:alpha", latency: "38 ms", bandwidth: "420 Mbps", throughput: "84 Mbps", usage: "12.4 GB", exitIp: "23.18.91.2", enabled: true },
  { id: "socks:home", latency: "92 ms", bandwidth: "180 Mbps", throughput: "41 Mbps", usage: "6.7 GB", exitIp: "45.77.11.9", enabled: false },
  { id: "http:edge", latency: "64 ms", bandwidth: "260 Mbps", throughput: "73 Mbps", usage: "9.1 GB", exitIp: "18.220.113.5", enabled: true },
];

const MOCK_RULES = [
  { id: "post-1", name: "Kids Safe Browsing", source: "Post", enabled: true, script: "match $REQ.host \"*.adult\" && reject;" },
  { id: "post-2", name: "Home Lab", source: "Post", enabled: false, script: "match $REQ.host \"lab.home\" && forward $TUNNEL.lab;" },
  { id: "cfg-1", name: "System Base", source: "Config", enabled: true, script: "call-server default;" },
];

const MOCK_DATABASES = [
  { id: "db-host-tag", kind: "Hostname TagDB", source: "subscription", readOnly: true, updatedAt: "2026-01-24 18:40" },
  { id: "db-ip-host", kind: "IP → Host", source: "probe", readOnly: true, updatedAt: "2026-01-24 18:52" },
  { id: "db-custom-tags", kind: "Custom Tags", source: "custom", readOnly: false, updatedAt: "2026-01-24 17:10" },
];

const Overview = () => {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefreshAt, setLastRefreshAt] = useState<Date>(new Date());

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      setLastRefreshAt(new Date());
    }, 10000);
    return () => clearInterval(timer);
  }, [autoRefresh]);

  const refreshNow = () => setLastRefreshAt(new Date());

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">System Overview</h2>
        <p className="section-desc">Real-time status of the CYFS Gateway Router mode.</p>
      </div>

      <div className="card mb-6">
        <div className="flex justify-between items-center">
          <div className="text-muted">
            Last refresh: <span className="text-mono">{lastRefreshAt.toLocaleTimeString("en-US", { hour12: false })}</span>
          </div>
          <div className="flex gap-2">
            <button className="dev-btn w-auto px-4 py-2" onClick={() => setAutoRefresh((value) => !value)}>
              Auto Refresh: {autoRefresh ? "On" : "Off"}
            </button>
            <button className="dev-btn w-auto px-4 py-2" onClick={refreshNow}>
              Manual Refresh
            </button>
          </div>
        </div>
      </div>
      
      <div className="card-grid">
        <SimpleCard title="Uptime" value="14d 02:33:12" label="Since last reboot" />
        <SimpleCard title="Throughput" value="1.2 GB/s" label="Current traffic load" />
        <SimpleCard title="Active Tunnels" value="24" label="Across 3 interfaces" />
        <SimpleCard title="Blocked Req" value="142" label="Last 24 hours" />
      </div>

      <h3 className="text-mono text-lg mt-8 mb-4">Recent Activity Log</h3>
      <div className="card p-0 overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Event</th>
              <th>Source</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="text-mono text-muted">2023-10-24 10:42:01</td>
              <td>New Device Connected</td>
              <td className="text-mono text-accent">iPhone-13-Pro</td>
              <td className="text-success">Authorized</td>
            </tr>
            <tr>
              <td className="text-mono text-muted">2023-10-24 10:40:15</td>
              <td>Rule Update</td>
              <td className="text-mono">System</td>
              <td className="text-success">Applied</td>
            </tr>
            <tr>
              <td className="text-mono text-muted">2023-10-24 09:12:33</td>
              <td>Connection Refused</td>
              <td className="text-mono text-muted">192.168.1.44</td>
              <td className="text-muted">Blocked</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

const Devices = () => (
  <div className="view-container">
    <div className="section-header">
      <h2 className="section-title">Connected Devices</h2>
      <p className="section-desc">Manage devices authorized to use this gateway.</p>
    </div>
    <div className="card">
      <div className="flex justify-between items-center mb-4">
        <h3 className="font-semibold">Device List</h3>
        <button className="dev-btn w-auto px-4 py-2">Add Device</button>
      </div>
      <table className="data-table">
        <thead>
          <tr>
            <th>Device Name</th>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Group</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {[1, 2, 3, 4].map((i) => (
            <tr key={i}>
              <td className="font-medium text-main">Workstation-0{i}</td>
              <td className="text-mono text-muted">192.168.1.10{i}</td>
              <td className="text-mono text-muted">00:1B:44:11:3A:B{i}</td>
              <td><span className="status-badge" style={{color: 'var(--text-main)', borderColor: 'var(--border-subtle)'}}>Default</span></td>
              <td className="text-mono text-success">Active now</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const Tunnels = () => {
  const [lastTraceId, setLastTraceId] = useState<string | null>(null);
  const [lastTestAt, setLastTestAt] = useState<Date | null>(null);

  const runTests = () => {
    const trace = `trace-${Math.random().toString(36).slice(2, 10)}`;
    setLastTraceId(trace);
    setLastTestAt(new Date());
  };

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">Tunnels</h2>
        <p className="section-desc">{MODULE_DESC.tunnels}</p>
      </div>
      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <h3 className="font-semibold">Tunnel List</h3>
          <button className="dev-btn w-auto px-4 py-2">Import Tunnel</button>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Latency</th>
              <th>Bandwidth</th>
              <th>Throughput</th>
              <th>Usage</th>
              <th>Exit IP</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_TUNNELS.map((tunnel) => (
              <tr key={tunnel.id}>
                <td className="text-mono text-muted">{tunnel.latency}</td>
                <td className="text-mono">{tunnel.bandwidth}</td>
                <td className="text-mono">{tunnel.throughput}</td>
                <td className="text-mono text-muted">{tunnel.usage}</td>
                <td className="text-mono">{tunnel.exitIp}</td>
                <td>{tunnel.enabled ? "Enabled" : "Disabled"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card mt-8">
        <h3 className="font-semibold mb-4">One-Click Test</h3>
        <p className="text-muted">Run predefined website tests and jump to logs with trace-id.</p>
        {lastTraceId && (
          <p className="text-mono text-muted mt-8">
            Last trace: {lastTraceId} ({lastTestAt?.toLocaleTimeString("en-US", { hour12: false })})
          </p>
        )}
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={runTests}>Run Tests</button>
          <button className="dev-btn w-auto px-4 py-2">Open Logs</button>
        </div>
      </div>
    </div>
  );
};

const Rules = () => {
  const [promptGeneratedAt, setPromptGeneratedAt] = useState<Date | null>(null);
  const [validationStatus, setValidationStatus] = useState<"idle" | "ok" | "error">("idle");
  const [lastAppliedAt, setLastAppliedAt] = useState<Date | null>(null);

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">Rules</h2>
        <p className="section-desc">{MODULE_DESC.rules}</p>
      </div>
      <div className="card mb-6">
        <h3 className="font-semibold mb-4">Rule Order</h3>
        <p className="text-muted">Rules are executed top to bottom. A terminal action stops evaluation. Post rules can be reordered.</p>
      </div>
      <div className="card mb-6">
        <h3 className="font-semibold mb-4">Create New Rule (Offline)</h3>
        <p className="text-muted">Describe intent in natural language, generate a prompt, paste the script, validate, then apply.</p>
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setPromptGeneratedAt(new Date())}>Generate Prompt</button>
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setValidationStatus("ok")}>Validate Script</button>
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setLastAppliedAt(new Date())}>Apply Rule</button>
        </div>
        <div className="text-muted mt-8">
          Prompt: {promptGeneratedAt ? promptGeneratedAt.toLocaleTimeString("en-US", { hour12: false }) : "Not generated"}
          <span className="mr-2"></span>
          Validation: {validationStatus === "idle" ? "Pending" : validationStatus.toUpperCase()}
          <span className="mr-2"></span>
          Applied: {lastAppliedAt ? lastAppliedAt.toLocaleTimeString("en-US", { hour12: false }) : "Not applied"}
        </div>
      </div>
      <div className="card">
        <h3 className="font-semibold mb-4">Rules List</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Source</th>
              <th>Status</th>
              <th>Script</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_RULES.map((rule) => (
              <tr key={rule.id}>
                <td className="font-medium text-main">{rule.name}</td>
                <td>{rule.source}</td>
                <td>{rule.enabled ? "Enabled" : "Disabled"}</td>
                <td className="text-mono text-muted">{rule.script}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const Databases = () => (
  <div className="view-container">
    <div className="section-header">
      <h2 className="section-title">Databases</h2>
      <p className="section-desc">{MODULE_DESC.databases}</p>
    </div>
    <div className="card">
      <h3 className="font-semibold mb-4">Database Sources</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Source</th>
            <th>Access</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {MOCK_DATABASES.map((db) => (
            <tr key={db.id}>
              <td className="font-medium text-main">{db.kind}</td>
              <td>{db.source}</td>
              <td>{db.readOnly ? "Read-only" : "Editable"}</td>
              <td className="text-mono text-muted">{db.updatedAt}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    <div className="card mt-8">
      <h3 className="font-semibold mb-4">Quick Query</h3>
      <p className="text-muted">Query IP → Host, IP → GEO, and hostname tags without online lookup.</p>
      <div className="flex gap-2 mt-8">
        <button className="dev-btn w-auto px-4 py-2">Query Host</button>
        <button className="dev-btn w-auto px-4 py-2">Query GEO</button>
      </div>
    </div>
  </div>
);

const Tests = () => {
  const [traceId, setTraceId] = useState<string | null>(null);
  const [lastRunAt, setLastRunAt] = useState<Date | null>(null);

  const runScenario = () => {
    const trace = `trace-${Math.random().toString(36).slice(2, 10)}`;
    setTraceId(trace);
    setLastRunAt(new Date());
  };

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">Scenario Tests</h2>
        <p className="section-desc">{MODULE_DESC.tests}</p>
      </div>
      <div className="card">
        <h3 className="font-semibold mb-4">Predefined Sites</h3>
        <p className="text-muted">Google, YouTube, Netflix, and Baidu are available by default.</p>
        {traceId && (
          <p className="text-mono text-muted mt-8">
            Last trace: {traceId} ({lastRunAt?.toLocaleTimeString("en-US", { hour12: false })})
          </p>
        )}
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={runScenario}>Run Scenario</button>
          <button className="dev-btn w-auto px-4 py-2">View Trace Log</button>
        </div>
      </div>
    </div>
  );
};

const Config = () => {
  const [draftStatus, setDraftStatus] = useState<"idle" | "validated" | "applied">("idle");
  const [lastAppliedAt, setLastAppliedAt] = useState<Date | null>(null);

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">Configuration</h2>
        <p className="section-desc">{MODULE_DESC.config}</p>
      </div>
      <div className="card mb-6">
        <h3 className="font-semibold mb-4">Effective Config</h3>
        <p className="text-muted">Merged config includes include expansion and parameter substitution.</p>
        <button className="dev-btn w-auto px-4 py-2 mt-8">Show Merged Config</button>
      </div>
      <div className="card">
        <h3 className="font-semibold mb-4">Draft Flow</h3>
        <p className="text-muted">Edit a draft, validate schema, preview diff, and apply with confirmation.</p>
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setDraftStatus("validated")}>Validate Draft</button>
          <button
            className="dev-btn w-auto px-4 py-2"
            onClick={() => {
              setDraftStatus("applied");
              setLastAppliedAt(new Date());
            }}
          >
            Apply Draft
          </button>
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setDraftStatus("idle")}>Rollback</button>
        </div>
        <div className="text-muted mt-8">
          Draft status: {draftStatus.toUpperCase()}
          <span className="mr-2"></span>
          Last applied: {lastAppliedAt ? lastAppliedAt.toLocaleTimeString("en-US", { hour12: false }) : "Not applied"}
        </div>
      </div>
    </div>
  );
};

const Settings = () => {
  const [uiMode, setUiMode] = useState<"router" | "ops" | "developer">("router");
  const [tlsEnabled, setTlsEnabled] = useState(false);

  return (
    <div className="view-container">
      <div className="section-header">
        <h2 className="section-title">System Settings</h2>
        <p className="section-desc">{MODULE_DESC.settings}</p>
      </div>
      <div className="card mb-6">
        <h3 className="font-semibold mb-4">UI Mode</h3>
        <p className="text-muted">Switch between Router, Ops, and Developer modes.</p>
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setUiMode("router")}>Router</button>
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setUiMode("ops")}>Ops</button>
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setUiMode("developer")}>Developer</button>
        </div>
        <div className="text-muted mt-8">Current mode: {uiMode.toUpperCase()}</div>
      </div>
      <div className="card">
        <h3 className="font-semibold mb-4">TLS MITM</h3>
        <p className="text-muted">TLS interception is disabled by default and requires explicit enablement.</p>
        <div className="flex gap-2 mt-8">
          <button className="dev-btn w-auto px-4 py-2" onClick={() => setTlsEnabled((value) => !value)}>
            {tlsEnabled ? "Disable" : "Enable"}
          </button>
          <button className="dev-btn w-auto px-4 py-2">Generate CA</button>
          <button className="dev-btn w-auto px-4 py-2">Rotate CA</button>
        </div>
        <div className="text-muted mt-8">TLS status: {tlsEnabled ? "Enabled" : "Disabled"}</div>
      </div>
    </div>
  );
};

// --- Navigation Config ---
const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: Icons.Grid, view: Overview },
  { id: 'devices', label: 'Devices', icon: Icons.Server, view: Devices },
  { id: 'tunnels', label: 'Tunnels', icon: Icons.Activity, view: Tunnels },
  { id: 'rules', label: 'Rules', icon: Icons.Shield, view: Rules },
  { id: 'databases', label: 'Databases', icon: Icons.Database, view: Databases },
  { id: 'tests', label: 'Tests', icon: Icons.Flask, view: Tests },
];

const SETTINGS_ITEMS = [
  { id: 'config', label: 'Config', icon: Icons.Settings, view: Config },
  { id: 'settings', label: 'Settings', icon: Icons.Settings, view: Settings },
];

// --- Main App Component ---

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const activeItem = [...NAV_ITEMS, ...SETTINGS_ITEMS].find(item => item.id === activeTab) || NAV_ITEMS[0];
  const ActiveView = activeItem.view;

  // Close mobile menu when tab changes
  useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [activeTab]);

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className={`sidebar ${isMobileMenuOpen ? 'open' : ''}`}>
        <div className="brand">
          <div className="brand-icon flex items-center justify-center">
            <Icons.Gateway />
          </div>
          <span>CYFS Gateway</span>
        </div>

        <div className="nav-section">
          <div className="nav-label">Monitoring</div>
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              className={`nav-item w-full ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <item.icon />
              {item.label}
            </button>
          ))}
        </div>

        <div className="nav-section mt-auto">
          <div className="nav-label">System</div>
          {SETTINGS_ITEMS.map(item => (
            <button
              key={item.id}
              className={`nav-item w-full ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <item.icon />
              {item.label}
            </button>
          ))}
        </div>

        <div className="dev-entry">
          <button className="dev-btn">
            <Icons.Code />
            Developer Panel
          </button>
        </div>
      </aside>

      {/* Topbar */}
      <header className="topbar">
        <div className="flex items-center">
          <button 
            className="mobile-menu-btn"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            <Icons.Menu />
          </button>
          <div className="breadcrumb">
            Dashboard / <span>{activeItem.label}</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="status-badge">
            <div className="status-dot"></div>
            ROUTER MODE
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-content">
        <ActiveView />
      </main>
    </div>
  );
}
