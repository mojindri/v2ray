import type { ReactNode } from "react";
import { Cable } from "lucide-react";

export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="auth-shell">
      <section className="auth-panel">
        <div className="brand auth-brand">
          <Cable size={25} />
          <span>Blackwire</span>
        </div>
        {children}
      </section>
    </div>
  );
}
