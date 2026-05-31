import { useState } from "react";
import { LockKeyhole } from "lucide-react";
import { Button } from "../components/atoms/Button";
import { Input } from "../components/atoms/Input";
import { Field } from "../components/molecules/Field";
import { AuthShell } from "../components/templates/AuthShell";

export function AuthPage({
  setupRequired,
  checking,
  error,
  onSubmit
}: {
  setupRequired: boolean;
  checking?: boolean;
  error: string;
  onSubmit: (username: string, password: string) => void;
}) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  return (
    <AuthShell>
      <div className="auth-copy">
        <h1>{checking ? "Checking panel" : setupRequired ? "Create admin" : "Panel login"}</h1>
        <p>
          {checking
            ? "Reading local panel status."
            : setupRequired
              ? "First run needs one local admin account."
              : "Use the local panel admin session."}
        </p>
      </div>
      <form
        className="auth-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (checking) return;
          onSubmit(username, password);
        }}
      >
        <Field label="Username">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </Field>
        <Field label="Password">
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={setupRequired ? "new-password" : "current-password"}
          />
        </Field>
        {error ? <div className="error-line">{error}</div> : null}
        <Button variant="primary" icon={<LockKeyhole size={16} />} disabled={checking}>
          {setupRequired ? "Create and enter" : "Login"}
        </Button>
      </form>
    </AuthShell>
  );
}
