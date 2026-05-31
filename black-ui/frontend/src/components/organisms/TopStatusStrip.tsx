import { CheckCircle2, LogOut, RefreshCw, ServerCog, XCircle } from "lucide-react";
import { Button } from "../atoms/Button";
import { StatusDot } from "../atoms/StatusDot";
import type { Status } from "../../lib/types";

export function TopStatusStrip({
  status,
  message,
  busy,
  onRefresh,
  onApply,
  onLogout
}: {
  status: Status | null;
  message: string;
  busy: boolean;
  onRefresh: () => void;
  onApply: () => void;
  onLogout: () => void;
}) {
  return (
    <header className="top-strip">
      <div className="top-status">
        <ServerCog size={17} />
        <StatusDot
          tone={status?.grpcReachable ? "green" : "amber"}
          label={status?.grpcReachable ? "gRPC connected" : "gRPC unavailable"}
        />
        <span className="strip-sep" />
        {message ? <span className="strip-message">{message}</span> : <span>Config path: {status?.configPath ?? "loading"}</span>}
      </div>
      <div className="top-actions">
        <Button variant="ghost" icon={<RefreshCw size={16} />} onClick={onRefresh} disabled={busy}>
          Refresh
        </Button>
        <Button variant="secondary" icon={status?.grpcReachable ? <CheckCircle2 size={16} /> : <XCircle size={16} />} onClick={onApply} disabled={busy}>
          Apply Config
        </Button>
        <Button variant="ghost" icon={<LogOut size={16} />} onClick={onLogout}>
          Logout
        </Button>
      </div>
    </header>
  );
}
