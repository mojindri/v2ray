import { useEffect, useState } from "react";
import { Plus, Save, Trash2 } from "lucide-react";
import type { CapabilityMap, Inbound, InboundInput } from "../lib/types";
import { Button } from "../components/atoms/Button";
import { Input, Select, Textarea } from "../components/atoms/Input";
import { Switch } from "../components/atoms/Switch";
import { Badge } from "../components/atoms/Badge";
import { Field } from "../components/molecules/Field";

const defaultInbound: InboundInput = {
  tag: "vless-main",
  listen: "0.0.0.0",
  port: 443,
  protocol: "vless",
  enabled: true,
  transport: "tcp",
  settings: "",
  streamSettings: "",
  sniffing: "",
  limits: ""
};

export function InboundsPage({
  inbounds,
  capabilities,
  busy,
  onCreate,
  onUpdate,
  onDelete
}: {
  inbounds: Inbound[];
  capabilities: CapabilityMap | null;
  busy: boolean;
  onCreate: (input: InboundInput) => void;
  onUpdate: (id: number, input: InboundInput) => void;
  onDelete: (id: number) => void;
}) {
  const [editing, setEditing] = useState<Inbound | null>(null);
  const [form, setForm] = useState<InboundInput>(defaultInbound);
  const protocolOptions = capabilities?.protocols.filter((p) => p.key !== "freedom") ?? [
    { key: "vless", label: "VLESS" },
    { key: "trojan", label: "Trojan" },
    { key: "shadowsocks", label: "Shadowsocks" },
    { key: "hysteria2", label: "Hysteria2" }
  ];
  const transportOptions = capabilities?.transports ?? [
    { key: "tcp", label: "TCP" },
    { key: "ws", label: "WebSocket" },
    { key: "reality", label: "REALITY" }
  ];

  useEffect(() => {
    if (!editing) return;
    setForm({
      tag: editing.tag,
      listen: editing.listen,
      port: editing.port,
      protocol: editing.protocol,
      enabled: editing.enabled,
      transport: editing.transport,
      settings: editing.settings,
      streamSettings: editing.streamSettings,
      sniffing: editing.sniffing,
      limits: editing.limits
    });
  }, [editing]);

  const submit = () => {
    editing ? onUpdate(editing.id, form) : onCreate(form);
    if (!editing) setForm(defaultInbound);
  };
  const canDeleteEditing = !busy && inbounds.length > 1;

  return (
    <div className="page">
      <div className="page-title">
        <h1>Inbounds</h1>
        <p>Blackwire inbound definitions. Common fields are structured; advanced protocol data stays as validated JSON.</p>
      </div>
      <div className="two-column">
        <section className="work-panel">
          <div className="panel-toolbar">
            <h2>Inbound list</h2>
            <Button variant="secondary" icon={<Plus size={16} />} onClick={() => { setEditing(null); setForm(defaultInbound); }}>
              New
            </Button>
          </div>
          <div className="stack-list">
            {inbounds.map((inbound) => (
              <button className="stack-row" key={inbound.id} onClick={() => setEditing(inbound)} type="button">
                <span>
                  <strong>{inbound.tag}</strong>
                  <small>{inbound.listen}:{inbound.port}</small>
                </span>
                <Badge tone={inbound.enabled ? "green" : "gray"}>{`${inbound.protocol} / ${inbound.transport}`}</Badge>
              </button>
            ))}
            {inbounds.length === 0 ? <div className="empty">Create the first VLESS inbound.</div> : null}
          </div>
        </section>
        <section className="work-panel editor-panel">
          <h2>{editing ? "Edit inbound" : "New inbound"}</h2>
          <Field label="Tag">
            <Input value={form.tag} onChange={(e) => setForm({ ...form, tag: e.target.value })} />
          </Field>
          <Field label="Listen host">
            <Input value={form.listen} onChange={(e) => setForm({ ...form, listen: e.target.value })} />
          </Field>
          <Field label="Port">
            <Input type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
          </Field>
          <Field label="Protocol">
            <Select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
              {protocolOptions.map((item) => (
                <option key={item.key} value={item.key}>{item.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="Transport">
            <Select value={form.transport} onChange={(e) => setForm({ ...form, transport: e.target.value })}>
              {transportOptions.map((item) => (
                <option key={item.key} value={item.key}>{item.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="Settings JSON" hint="Protocol-specific settings. For managed users, Black UI merges enabled panel users into clients.">
            <Textarea
              rows={7}
              value={form.settings ?? ""}
              onChange={(e) => setForm({ ...form, settings: e.target.value })}
              placeholder='{"clients":[]}'
            />
          </Field>
          <Field label="Stream settings JSON" hint="Transport/security settings. Required for REALITY and advanced transports.">
            <Textarea
              rows={8}
              value={form.streamSettings ?? ""}
              onChange={(e) => setForm({ ...form, streamSettings: e.target.value })}
              placeholder='{"network":"ws","security":"none","wsSettings":{"path":"/vless-main"}}'
            />
          </Field>
          <Field label="Sniffing JSON">
            <Textarea
              rows={4}
              value={form.sniffing ?? ""}
              onChange={(e) => setForm({ ...form, sniffing: e.target.value })}
              placeholder='{"enabled":true,"destOverride":["http","tls"]}'
            />
          </Field>
          <Field label="Limits JSON">
            <Textarea
              rows={4}
              value={form.limits ?? ""}
              onChange={(e) => setForm({ ...form, limits: e.target.value })}
              placeholder='{"maxConnections":10000,"maxHandshakeSeconds":10}'
            />
          </Field>
          <Switch checked={form.enabled} onChange={(enabled) => setForm({ ...form, enabled })} label="Inbound enabled" />
          <div className="button-row">
            {editing ? (
              <Button
                variant="danger"
                icon={<Trash2 size={16} />}
                onClick={() => onDelete(editing.id)}
                disabled={!canDeleteEditing}
                title={canDeleteEditing ? "Delete inbound" : "Create another inbound before deleting this one"}
              >
                Delete
              </Button>
            ) : null}
            <Button variant="primary" icon={<Save size={16} />} onClick={submit} disabled={busy}>
              Save Inbound
            </Button>
          </div>
          {editing && inbounds.length <= 1 ? (
            <p className="field-hint">Create another inbound before deleting this one.</p>
          ) : null}
        </section>
      </div>
    </div>
  );
}
