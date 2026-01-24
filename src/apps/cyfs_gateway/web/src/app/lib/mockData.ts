// Mock data for CYFS Gateway Dashboard

export interface Device {
  id: string;
  name: string;
  ip: string;
  mac: string;
  online: boolean;
  type: string;
  manufacturer: string;
  lastSeen: string;
  dataUsage: number;
  tlsEnabled: boolean;
}

export interface Tunnel {
  id: string;
  name: string;
  schema: string;
  endpoint: string;
  latency: number;
  bandwidth: number;
  throughput: number;
  dataUsage: number;
  exitIP: string;
  enabled: boolean;
  status: 'active' | 'idle' | 'error';
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  script: string;
  enabled: boolean;
  type: 'post' | 'config';
  source: string;
  priority: number;
  hitCount: number;
  lastTriggered: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  traceId?: string;
  source: string;
}

export interface Connection {
  id: string;
  tunnelId: string;
  deviceIP: string;
  protocol: string;
  host: string;
  status: 'active' | 'closed';
  bytesIn: number;
  bytesOut: number;
  duration: number;
}

export const mockDevices: Device[] = [
  {
    id: '1',
    name: 'iPhone 13 Pro',
    ip: '192.168.1.100',
    mac: '00:1A:2B:3C:4D:5E',
    online: true,
    type: 'smartphone',
    manufacturer: 'Apple',
    lastSeen: '2 分钟前',
    dataUsage: 1024 * 1024 * 250,
    tlsEnabled: true,
  },
  {
    id: '2',
    name: 'MacBook Pro',
    ip: '192.168.1.101',
    mac: '00:1A:2B:3C:4D:5F',
    online: true,
    type: 'laptop',
    manufacturer: 'Apple',
    lastSeen: '1 分钟前',
    dataUsage: 1024 * 1024 * 1024 * 2.5,
    tlsEnabled: false,
  },
  {
    id: '3',
    name: 'Galaxy S23',
    ip: '192.168.1.102',
    mac: '00:1A:2B:3C:4D:60',
    online: false,
    type: 'smartphone',
    manufacturer: 'Samsung',
    lastSeen: '2 小时前',
    dataUsage: 1024 * 1024 * 180,
    tlsEnabled: false,
  },
  {
    id: '4',
    name: 'iPad Air',
    ip: '192.168.1.103',
    mac: '00:1A:2B:3C:4D:61',
    online: true,
    type: 'tablet',
    manufacturer: 'Apple',
    lastSeen: '5 分钟前',
    dataUsage: 1024 * 1024 * 450,
    tlsEnabled: true,
  },
];

export const mockTunnels: Tunnel[] = [
  {
    id: 'tunnel1',
    name: '香港节点 HK-01',
    schema: 'wireguard',
    endpoint: 'hk01.example.com:51820',
    latency: 45,
    bandwidth: 1000,
    throughput: 125,
    dataUsage: 1024 * 1024 * 1024 * 5.2,
    exitIP: '203.0.113.1',
    enabled: true,
    status: 'active',
  },
  {
    id: 'tunnel2',
    name: '美国节点 US-01',
    schema: 'shadowsocks',
    endpoint: 'us01.example.com:8388',
    latency: 180,
    bandwidth: 500,
    throughput: 62.5,
    dataUsage: 1024 * 1024 * 1024 * 2.8,
    exitIP: '198.51.100.1',
    enabled: true,
    status: 'active',
  },
  {
    id: 'tunnel3',
    name: '日本节点 JP-01',
    schema: 'v2ray',
    endpoint: 'jp01.example.com:443',
    latency: 75,
    bandwidth: 800,
    throughput: 100,
    dataUsage: 1024 * 1024 * 1024 * 1.5,
    exitIP: '192.0.2.1',
    enabled: false,
    status: 'idle',
  },
];

export const mockRules: Rule[] = [
  {
    id: 'rule1',
    name: '特定网站走香港节点',
    description: '将 Google/YouTube 等网站流量转发到香港节点',
    script: `if (\${REQ.dest_host} match "google.com|youtube.com") {
  forward("wireguard://tunnel1/stream1");
}`,
    enabled: true,
    type: 'post',
    source: 'dashboard',
    priority: 1,
    hitCount: 1250,
    lastTriggered: '5 分钟前',
  },
  {
    id: 'rule2',
    name: '儿童设备内容过滤',
    description: '限制特定设备访问成人内容网站',
    script: `if (\${REQ.src_ip} == "192.168.1.103" && \${REQ.dest_host_tag} contains "adult") {
  reject("blocked by parental control");
}`,
    enabled: true,
    type: 'post',
    source: 'dashboard',
    priority: 2,
    hitCount: 45,
    lastTriggered: '2 小时前',
  },
  {
    id: 'rule3',
    name: '国内网站直连',
    description: '中国大陆网站直接连接，不走代理',
    script: `if (\${REQ.dest_ip_geo} == "CN") {
  accept();
}`,
    enabled: true,
    type: 'config',
    source: 'config/base.json',
    priority: 0,
    hitCount: 5430,
    lastTriggered: '1 分钟前',
  },
];

export const mockLogs: LogEntry[] = [
  {
    id: 'log1',
    timestamp: new Date().toISOString(),
    level: 'info',
    message: '规则 "特定网站走香港节点" 命中，转发到 tunnel1',
    traceId: 'trace-123456',
    source: 'process-chain',
  },
  {
    id: 'log2',
    timestamp: new Date(Date.now() - 60000).toISOString(),
    level: 'debug',
    message: 'Tunnel tunnel1 连接建立成功',
    source: 'tunnel-manager',
  },
  {
    id: 'log3',
    timestamp: new Date(Date.now() - 120000).toISOString(),
    level: 'warn',
    message: 'Device 192.168.1.102 已离线',
    source: 'device-monitor',
  },
  {
    id: 'log4',
    timestamp: new Date(Date.now() - 180000).toISOString(),
    level: 'error',
    message: 'Tunnel tunnel3 连接失败: timeout',
    source: 'tunnel-manager',
  },
];

export const mockConnections: Connection[] = [
  {
    id: 'conn1',
    tunnelId: 'tunnel1',
    deviceIP: '192.168.1.100',
    protocol: 'https',
    host: 'www.google.com',
    status: 'active',
    bytesIn: 1024 * 150,
    bytesOut: 1024 * 45,
    duration: 125,
  },
  {
    id: 'conn2',
    tunnelId: 'tunnel1',
    deviceIP: '192.168.1.101',
    protocol: 'https',
    host: 'www.youtube.com',
    status: 'active',
    bytesIn: 1024 * 1024 * 5,
    bytesOut: 1024 * 256,
    duration: 580,
  },
  {
    id: 'conn3',
    tunnelId: 'tunnel2',
    deviceIP: '192.168.1.100',
    protocol: 'https',
    host: 'www.netflix.com',
    status: 'active',
    bytesIn: 1024 * 1024 * 15,
    bytesOut: 1024 * 512,
    duration: 1250,
  },
];

// Traffic data for charts
export const mockTrafficData = Array.from({ length: 20 }, (_, i) => ({
  time: `${i}s`,
  upload: Math.random() * 1000,
  download: Math.random() * 2000,
}));

export const mockDeviceTraffic = [
  { name: 'iPhone 13 Pro', value: 250 },
  { name: 'MacBook Pro', value: 2500 },
  { name: 'Galaxy S23', value: 180 },
  { name: 'iPad Air', value: 450 },
];

export const mockTunnelTraffic = [
  { name: 'HK-01', value: 5200 },
  { name: 'US-01', value: 2800 },
  { name: 'JP-01', value: 1500 },
];

export const mockActionStats = [
  { name: '直连', value: 5430 },
  { name: '代理', value: 1295 },
  { name: '拦截', value: 45 },
  { name: '失败', value: 12 },
];

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}