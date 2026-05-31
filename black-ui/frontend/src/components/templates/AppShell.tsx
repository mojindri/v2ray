import type { ReactNode } from "react";
import type { PageKey, Status } from "../../lib/types";
import { AppSidebar } from "../organisms/AppSidebar";
import { TopStatusStrip } from "../organisms/TopStatusStrip";

export function AppShell({
  page,
  status,
  message,
  busy,
  children,
  onPage,
  onRefresh,
  onApply,
  onLogout
}: {
  page: PageKey;
  status: Status | null;
  message: string;
  busy: boolean;
  children: ReactNode;
  onPage: (page: PageKey) => void;
  onRefresh: () => void;
  onApply: () => void;
  onLogout: () => void;
}) {
  return (
    <div className="app-shell">
      <AppSidebar page={page} onPage={onPage} />
      <main className="main">
        <TopStatusStrip status={status} message={message} busy={busy} onRefresh={onRefresh} onApply={onApply} onLogout={onLogout} />
        {children}
      </main>
    </div>
  );
}
