import { RotateCcw, ServerCog } from "lucide-react";
import type { ServiceStatus } from "../lib/types";
import { Badge } from "../components/atoms/Badge";
import { Button } from "../components/atoms/Button";

export function ServicePage({
  service,
  busy,
  onRestart
}: {
  service: ServiceStatus | null;
  busy: boolean;
  onRestart: () => void;
}) {
  return (
    <div className="page">
      <div className="page-title">
        <h1>Service</h1>
        <p>Linux service status and recent Blackwire logs.</p>
      </div>
      <section className="work-panel split-panel">
        <div>
          <h2>Blackwire systemd</h2>
          <div className="mini-list">
            <div>
              <span>systemd</span>
              <Badge tone={service?.systemdAvailable ? "green" : "amber"}>{service?.systemdAvailable ? "available" : "unavailable"}</Badge>
            </div>
            <div>
              <span>active state</span>
              <strong>{service?.activeState ?? "unknown"}</strong>
            </div>
            <div>
              <span>sub state</span>
              <strong>{service?.subState ?? "unknown"}</strong>
            </div>
          </div>
          <Button variant="primary" icon={<RotateCcw size={16} />} onClick={onRestart} disabled={busy || !service?.systemdAvailable}>
            Restart Blackwire
          </Button>
        </div>
        <div>
          <h2>Recent logs</h2>
          <pre className="command-box service-log"><ServerCog size={18} />{(service?.logs ?? []).join("\n") || "No logs available."}</pre>
        </div>
      </section>
    </div>
  );
}
