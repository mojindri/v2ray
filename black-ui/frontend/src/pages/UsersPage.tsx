import { useMemo, useState } from "react";
import type { AppData, ManagedUser, UserInput } from "../lib/types";
import { UserDrawer } from "../components/organisms/UserDrawer";
import { UserTable } from "../components/organisms/UserTable";

export function UsersPage({
  data,
  busy,
  onSave,
  onUuid,
  onToggle,
  onDelete,
  onReset,
  onRotateUuid,
  onRotateToken,
  onBulk
}: {
  data: AppData;
  busy: boolean;
  onSave: (id: number | null, input: UserInput) => void;
  onUuid: () => Promise<string>;
  onToggle: (user: ManagedUser) => void;
  onDelete: (user: ManagedUser) => void;
  onReset: (user: ManagedUser) => void;
  onRotateUuid: (user: ManagedUser) => void;
  onRotateToken: (user: ManagedUser) => void;
  onBulk: (ids: number[], action: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<ManagedUser | null>(null);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return data.users;
    return data.users.filter((user) =>
      [user.email, user.uuid, user.note, user.enforcementStatus].some((field) => field.toLowerCase().includes(needle))
    );
  }, [data.users, query]);

  const openEditor = (user: ManagedUser | null) => {
    setEditing(user);
    setDrawerOpen(true);
  };

  return (
    <div className="page">
      <div className="page-title">
        <h1>Users</h1>
        <p>One panel user maps to one VLESS client.</p>
      </div>
      <UserTable
        users={filtered}
        inbounds={data.inbounds}
        settings={data.settings}
        query={query}
        selectedIds={selectedIds}
        onQuery={setQuery}
        onAdd={() => openEditor(null)}
        onEdit={openEditor}
        onToggle={onToggle}
        onDelete={onDelete}
        onReset={onReset}
        onBulk={(action) => onBulk([...selectedIds], action)}
        onSelect={(id, selected) =>
          setSelectedIds((current) => {
            const next = new Set(current);
            selected ? next.add(id) : next.delete(id);
            return next;
          })
        }
        onSelectAll={(selected) => setSelectedIds(selected ? new Set(filtered.map((u) => u.id)) : new Set())}
      />
      <UserDrawer
        open={drawerOpen}
        user={editing}
        inbounds={data.inbounds}
        settings={data.settings}
        busy={busy}
        onClose={() => setDrawerOpen(false)}
        onSubmit={(id, input) => {
          onSave(id, input);
          setDrawerOpen(false);
        }}
        onUuid={onUuid}
        onRotateUuid={onRotateUuid}
        onRotateToken={onRotateToken}
        onReset={onReset}
      />
    </div>
  );
}
