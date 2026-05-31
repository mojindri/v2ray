import { Activity, CircleGauge, Database, Users } from "lucide-react";
import type { ReactNode } from "react";
import type { AppData } from "../lib/types";
import { formatBytes } from "../lib/format";

export function DashboardPage({ data }: { data: AppData }) {
  const totalUpload = data.users.reduce((sum, user) => sum + user.uploadBytes, 0);
  const totalDownload = data.users.reduce((sum, user) => sum + user.downloadBytes, 0);
  return (
    <div className="page">
      <div className="page-title">
        <h1>Dashboard</h1>
        <p>Runtime health, traffic, and Blackwire-native panel shape.</p>
      </div>
      <div className="metric-grid">
        <Metric icon={<Users />} label="Active users" value={`${data.status?.activeUsers ?? 0}`} sub={`${data.status?.users ?? 0} total`} />
        <Metric icon={<CircleGauge />} label="Traffic" value={formatBytes(totalUpload + totalDownload)} sub={`${formatBytes(totalUpload)} up · ${formatBytes(totalDownload)} down`} />
        <Metric icon={<Database />} label="Endpoints" value={`${data.status?.inbounds ?? 0}`} sub={`${data.status?.outbounds ?? 0} outbounds`} />
        <Metric icon={<Activity />} label="Runtime" value={data.status?.grpcReachable ? "Live" : "Offline"} sub={data.status?.grpcAddress ?? "127.0.0.1:62789"} />
      </div>
      <section className="work-panel split-panel">
        <div>
          <h2>Traffic by inbound</h2>
          <div className="mini-list">
            {data.traffic.inbounds.map((row) => (
              <div key={row.tag}>
                <span>{row.tag}</span>
                <strong>{formatBytes(row.uploadBytes + row.downloadBytes)}</strong>
              </div>
            ))}
            {data.traffic.inbounds.length === 0 ? <p>No live inbound traffic available.</p> : null}
          </div>
        </div>
        <div>
          <h2>Run command</h2>
          <pre className="command-box">{data.status?.runCommand ?? "blackwire run -c black-ui/data/config.json"}</pre>
        </div>
      </section>
    </div>
  );
}

function Metric({ icon, label, value, sub }: { icon: ReactNode; label: string; value: string; sub: string }) {
  return (
    <section className="metric">
      <span className="metric-icon">{icon}</span>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{sub}</small>
    </section>
  );
}
