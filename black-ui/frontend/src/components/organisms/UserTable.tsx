import { Copy, Plus, RotateCcw } from "lucide-react";
import { useState } from "react";
import type { Inbound, ManagedUser, Settings } from "../../lib/types";
import { copyText } from "../../lib/clipboard";
import { formatBytes, formatDate } from "../../lib/format";
import { subscriptionUrl } from "../../lib/subscription";
import { Badge } from "../atoms/Badge";
import { Button } from "../atoms/Button";
import { IconButton } from "../atoms/IconButton";
import { ActionMenu } from "../molecules/ActionMenu";
import { QuotaMeter } from "../molecules/QuotaMeter";
import { SearchBar } from "../molecules/SearchBar";

function statusTone(user: ManagedUser): "green" | "red" | "gray" | "amber" {
  if (!user.enabled) return "gray";
  if (user.enforcementStatus === "active") return "green";
  if (user.enforcementStatus.includes("expired") || user.enforcementStatus.includes("quota")) return "red";
  return "amber";
}

export function UserTable({
  users,
  inbounds,
  settings,
  query,
  selectedIds,
  onQuery,
  onAdd,
  onEdit,
  onToggle,
  onDelete,
  onSelect,
  onSelectAll,
  onReset,
  onBulk
}: {
  users: ManagedUser[];
  inbounds: Inbound[];
  settings: Settings | null;
  query: string;
  selectedIds: Set<number>;
  onQuery: (value: string) => void;
  onAdd: () => void;
  onEdit: (user: ManagedUser) => void;
  onToggle: (user: ManagedUser) => void;
  onDelete: (user: ManagedUser) => void;
  onSelect: (id: number, selected: boolean) => void;
  onSelectAll: (selected: boolean) => void;
  onReset: (user: ManagedUser) => void;
  onBulk: (action: string) => void;
}) {
  const [copyFeedback, setCopyFeedback] = useState("");
  const inboundById = new Map(inbounds.map((inbound) => [inbound.id, inbound]));
  const allSelected = users.length > 0 && users.every((user) => selectedIds.has(user.id));
  const copySubscription = async (value: string) => {
    const result = await copyText(value);
    setCopyFeedback(result.message);
    window.setTimeout(() => setCopyFeedback(""), 2200);
  };

  return (
    <section className="work-panel">
      <div className="panel-toolbar">
        <SearchBar value={query} onChange={onQuery} />
        <select className="input compact" onChange={(event) => event.target.value && onBulk(event.target.value)} value="">
          <option value="">Bulk actions</option>
          <option value="enable">Enable selected</option>
          <option value="disable">Disable selected</option>
          <option value="resetUsage">Reset usage</option>
          <option value="delete">Delete selected</option>
        </select>
        <Button variant="primary" icon={<Plus size={16} />} onClick={onAdd}>
          Add User
        </Button>
      </div>
      {copyFeedback ? (
        <div className={copyFeedback === "Copied" ? "copy-feedback" : "copy-feedback copy-feedback-error"} aria-live="polite">
          {copyFeedback}
        </div>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="check-cell">
                <input type="checkbox" checked={allSelected} onChange={(e) => onSelectAll(e.target.checked)} />
              </th>
              <th>Email</th>
              <th>Status</th>
              <th>Inbound</th>
              <th>Quota</th>
              <th>Expiry</th>
              <th>Upload</th>
              <th>Download</th>
              <th>Sub</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => {
              const inbound = inboundById.get(user.inboundId);
              const subUrl = subscriptionUrl(settings, user.subToken);
              return (
                <tr key={user.id} className={selectedIds.has(user.id) ? "row-selected" : ""}>
                  <td className="check-cell">
                    <input type="checkbox" checked={selectedIds.has(user.id)} onChange={(e) => onSelect(user.id, e.target.checked)} />
                  </td>
                  <td>
                    <button className="link-cell" onClick={() => onEdit(user)} type="button">
                      {user.email}
                    </button>
                    <small>{user.note || user.uuid}</small>
                  </td>
                  <td>
                    <Badge tone={statusTone(user)}>{user.enabled ? user.enforcementStatus : "disabled"}</Badge>
                  </td>
                  <td>{inbound?.tag ?? "Missing"}</td>
                  <td>
                    <QuotaMeter upload={user.uploadBytes} download={user.downloadBytes} limit={user.trafficLimitBytes} />
                  </td>
                  <td>{formatDate(user.expiryAt)}</td>
                  <td>{formatBytes(user.uploadBytes)}</td>
                  <td>{formatBytes(user.downloadBytes)}</td>
                  <td>
                    <div className="inline-icons">
                      <IconButton label="Copy subscription URL" onClick={() => copySubscription(subUrl)}>
                        <Copy size={16} />
                      </IconButton>
                      <IconButton label="Reset usage" onClick={() => onReset(user)}>
                        <RotateCcw size={16} />
                      </IconButton>
                    </div>
                  </td>
                  <td>
                    <ActionMenu
                      enabled={user.enabled}
                      onEdit={() => onEdit(user)}
                      onToggle={() => onToggle(user)}
                      onDelete={() => onDelete(user)}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {users.length === 0 ? <div className="empty">No users match the current view.</div> : null}
      </div>
    </section>
  );
}
