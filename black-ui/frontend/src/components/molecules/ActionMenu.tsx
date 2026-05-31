import { MoreVertical } from "lucide-react";
import { IconButton } from "../atoms/IconButton";

export function ActionMenu({
  onEdit,
  onToggle,
  onDelete,
  enabled
}: {
  onEdit: () => void;
  onToggle: () => void;
  onDelete: () => void;
  enabled: boolean;
}) {
  return (
    <div className="actions">
      <IconButton label="Open actions">
        <MoreVertical size={16} />
      </IconButton>
      <div className="actions-menu">
        <button onClick={onEdit}>Edit</button>
        <button onClick={onToggle}>{enabled ? "Disable" : "Enable"}</button>
        <button className="danger-text" onClick={onDelete}>
          Delete
        </button>
      </div>
    </div>
  );
}
