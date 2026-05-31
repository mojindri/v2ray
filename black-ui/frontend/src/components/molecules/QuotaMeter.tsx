import { formatBytes, quotaPercent } from "../../lib/format";

export function QuotaMeter({
  upload,
  download,
  limit
}: {
  upload: number;
  download: number;
  limit: number | null;
}) {
  const pct = quotaPercent(upload, download, limit);
  const tone = pct >= 95 ? "danger" : pct >= 75 ? "warn" : "ok";
  return (
    <div className="quota">
      <div className="quota-line">
        <span>{limit ? `${pct}%` : "Unlimited"}</span>
        <span>
          {formatBytes(upload + download)}
          {limit ? ` / ${formatBytes(limit)}` : ""}
        </span>
      </div>
      <span className="quota-track">
        <span className={`quota-fill quota-${tone}`} style={{ width: `${limit ? pct : 12}%` }} />
      </span>
    </div>
  );
}
