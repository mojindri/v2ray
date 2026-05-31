import { Copy, KeyRound, RotateCcw, Save, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { Inbound, ManagedUser, Settings, UserInput } from "../../lib/types";
import { copyText } from "../../lib/clipboard";
import { formatBytes, fromInputDateTime, toInputDateTime } from "../../lib/format";
import { Button } from "../atoms/Button";
import { IconButton } from "../atoms/IconButton";
import { Input, Select, Textarea } from "../atoms/Input";
import { Switch } from "../atoms/Switch";
import { Field } from "../molecules/Field";

const emptyForm = (inboundId: number): UserInput => ({
  inboundId,
  email: "",
  uuid: "",
  flow: "",
  credential: {},
  note: "",
  enabled: true,
  trafficLimitBytes: null,
  expiryAt: null
});

export function UserDrawer({
  open,
  user,
  inbounds,
  settings,
  onClose,
  onSubmit,
  onUuid,
  onRotateUuid,
  onRotateToken,
  onReset,
  busy
}: {
  open: boolean;
  user: ManagedUser | null;
  inbounds: Inbound[];
  settings: Settings | null;
  onClose: () => void;
  onSubmit: (id: number | null, input: UserInput) => void;
  onUuid: () => Promise<string>;
  onRotateUuid: (user: ManagedUser) => void;
  onRotateToken: (user: ManagedUser) => void;
  onReset: (user: ManagedUser) => void;
  busy: boolean;
}) {
  const defaultInboundId = inbounds[0]?.id ?? 0;
  const [form, setForm] = useState<UserInput>(emptyForm(defaultInboundId));
  const [expiryLocal, setExpiryLocal] = useState("");
  const [credentialText, setCredentialText] = useState("{}");
  const [copyFeedback, setCopyFeedback] = useState("");
  const subUrl = useMemo(() => (user && settings ? `${settings.publicBaseUrl}/sub/${user.subToken}` : ""), [settings, user]);

  useEffect(() => {
    if (user) {
      setForm({
        inboundId: user.inboundId,
        email: user.email,
        uuid: user.uuid,
        flow: user.flow,
        credential: user.credential,
        note: user.note,
        enabled: user.enabled,
        trafficLimitBytes: user.trafficLimitBytes,
        expiryAt: user.expiryAt
      });
      setCredentialText(JSON.stringify(user.credential ?? {}, null, 2));
      setExpiryLocal(toInputDateTime(user.expiryAt));
    } else {
      setForm(emptyForm(defaultInboundId));
      setCredentialText("{}");
      setExpiryLocal("");
    }
  }, [defaultInboundId, user]);

  if (!open) return null;

  const submit = () => {
    try {
      onSubmit(user?.id ?? null, { ...form, credential: JSON.parse(credentialText), expiryAt: fromInputDateTime(expiryLocal) });
    } catch (error) {
      window.alert(error instanceof Error ? error.message : String(error));
    }
  };
  const copySubscription = async () => {
    const result = await copyText(subUrl);
    setCopyFeedback(result.ok ? "Copied" : "Copy failed. Select the URL and copy manually.");
    window.setTimeout(() => setCopyFeedback(""), 2600);
  };

  return (
    <aside className="drawer">
      <div className="drawer-head">
        <div>
          <h2>{user ? user.email : "New user"}</h2>
          <p>{user ? "Manage one protocol credential." : "Create a protocol credential for an inbound."}</p>
        </div>
        <IconButton label="Close" onClick={onClose}>
          <X size={18} />
        </IconButton>
      </div>
      <div className="drawer-body">
        <Field label="Email">
          <Input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="alice@example.com" />
        </Field>
        <Field label="Inbound">
          <Select value={form.inboundId} onChange={(e) => setForm({ ...form, inboundId: Number(e.target.value) })}>
            {inbounds.map((inbound) => (
              <option key={inbound.id} value={inbound.id}>
                {inbound.tag} :{inbound.port}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="UUID">
          <div className="inline-field">
            <Input value={form.uuid} onChange={(e) => setForm({ ...form, uuid: e.target.value })} />
            <IconButton label="Generate UUID" onClick={async () => setForm({ ...form, uuid: await onUuid() })}>
              <KeyRound size={17} />
            </IconButton>
          </div>
        </Field>
        <Field label="Flow" hint="Leave empty for normal VLESS clients.">
          <Input value={form.flow ?? ""} onChange={(e) => setForm({ ...form, flow: e.target.value })} placeholder="xtls-rprx-vision" />
        </Field>
        <Field label="Credential JSON" hint='Protocol-specific fields, such as {"password":"..."} for Trojan/SS or {"auth":"..."} for Hysteria2.'>
          <Textarea rows={6} value={credentialText} onChange={(e) => setCredentialText(e.target.value)} />
        </Field>
        <Field label="Traffic limit" hint="Set 0 or leave empty for unlimited.">
          <Input
            type="number"
            min={0}
            value={form.trafficLimitBytes ?? ""}
            onChange={(e) => setForm({ ...form, trafficLimitBytes: e.target.value ? Number(e.target.value) : null })}
            placeholder="10737418240"
          />
        </Field>
        <Field label="Expiry">
          <Input type="datetime-local" value={expiryLocal} onChange={(e) => setExpiryLocal(e.target.value)} />
        </Field>
        <Field label="Note">
          <Textarea rows={3} value={form.note ?? ""} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        </Field>
        <Switch checked={form.enabled} onChange={(enabled) => setForm({ ...form, enabled })} label="User enabled" />
        {user ? (
          <div className="drawer-card">
            <h3>Current usage</h3>
            <p>
              Upload {formatBytes(user.uploadBytes)} · Download {formatBytes(user.downloadBytes)} · Total{" "}
              {formatBytes(user.uploadBytes + user.downloadBytes)}
            </p>
            <div className="drawer-actions">
              <Button variant="secondary" icon={<RotateCcw size={16} />} onClick={() => onReset(user)}>
                Reset usage
              </Button>
              <Button variant="secondary" icon={<KeyRound size={16} />} onClick={() => onRotateUuid(user)}>
                Rotate UUID
              </Button>
              <Button variant="secondary" icon={<KeyRound size={16} />} onClick={() => onRotateToken(user)}>
                Rotate token
              </Button>
            </div>
            <div className="copy-row">
              <Input value={subUrl} readOnly />
              <IconButton label="Copy subscription URL" onClick={copySubscription}>
                <Copy size={16} />
              </IconButton>
            </div>
            {copyFeedback ? (
              <div className={copyFeedback === "Copied" ? "copy-feedback" : "copy-feedback copy-feedback-error"} aria-live="polite">
                {copyFeedback}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
      <div className="drawer-foot">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="primary" icon={<Save size={16} />} onClick={submit} disabled={busy || inbounds.length === 0}>
          Save User
        </Button>
      </div>
    </aside>
  );
}
