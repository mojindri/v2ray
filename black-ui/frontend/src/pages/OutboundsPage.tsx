import { useEffect, useState } from "react";
import { Plus, Save, Trash2 } from "lucide-react";
import type { CapabilityMap, Outbound, OutboundInput } from "../lib/types";
import { Button } from "../components/atoms/Button";
import { Input, Select, Textarea } from "../components/atoms/Input";
import { Switch } from "../components/atoms/Switch";
import { Badge } from "../components/atoms/Badge";
import { Field } from "../components/molecules/Field";

const defaultOutbound: OutboundInput = {
  tag: "freedom",
  protocol: "freedom",
  enabled: true,
  settings: "{}",
  streamSettings: ""
};

export function OutboundsPage({
  outbounds,
  capabilities,
  busy,
  onCreate,
  onUpdate,
  onDelete
}: {
  outbounds: Outbound[];
  capabilities: CapabilityMap | null;
  busy: boolean;
  onCreate: (input: OutboundInput) => void;
  onUpdate: (id: number, input: OutboundInput) => void;
  onDelete: (id: number) => void;
}) {
  const [editing, setEditing] = useState<Outbound | null>(null);
  const [form, setForm] = useState<OutboundInput>(defaultOutbound);
  const protocols = capabilities?.protocols.filter((p) => ["freedom", "vless", "vmess", "trojan", "shadowsocks", "hysteria2"].includes(p.key)) ?? [
    { key: "freedom", label: "Freedom", status: "supported", notes: "" },
    { key: "vless", label: "VLESS", status: "supported", notes: "" },
    { key: "trojan", label: "Trojan", status: "supported", notes: "" }
  ];

  useEffect(() => {
    if (!editing) return;
    setForm({
      tag: editing.tag,
      protocol: editing.protocol,
      enabled: editing.enabled,
      settings: editing.settings,
      streamSettings: editing.streamSettings
    });
  }, [editing]);

  const submit = () => {
    editing ? onUpdate(editing.id, form) : onCreate(form);
    if (!editing) setForm(defaultOutbound);
  };

  return (
    <div className="page">
      <div className="page-title">
        <h1>Outbounds</h1>
        <p>Blackwire outbound definitions. Advanced protocol settings are stored as validated JSON.</p>
      </div>
      <div className="two-column">
        <section className="work-panel">
          <div className="panel-toolbar">
            <h2>Outbound list</h2>
            <Button variant="secondary" icon={<Plus size={16} />} onClick={() => { setEditing(null); setForm(defaultOutbound); }}>
              New
            </Button>
          </div>
          <div className="stack-list">
            {outbounds.map((outbound) => (
              <button className="stack-row" key={outbound.id} onClick={() => setEditing(outbound)} type="button">
                <span>
                  <strong>{outbound.tag}</strong>
                  <small>{outbound.protocol}</small>
                </span>
                <Badge tone={outbound.enabled ? "green" : "gray"}>{outbound.enabled ? "enabled" : "disabled"}</Badge>
              </button>
            ))}
            {outbounds.length === 0 ? <div className="empty">Create the first outbound.</div> : null}
          </div>
        </section>
        <section className="work-panel editor-panel">
          <h2>{editing ? "Edit outbound" : "New outbound"}</h2>
          <Field label="Tag">
            <Input value={form.tag} onChange={(e) => setForm({ ...form, tag: e.target.value })} />
          </Field>
          <Field label="Protocol">
            <Select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
              {protocols.map((item) => (
                <option key={item.key} value={item.key}>{item.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="Settings JSON">
            <Textarea rows={9} value={form.settings ?? ""} onChange={(e) => setForm({ ...form, settings: e.target.value })} placeholder='{"address":"example.com","port":443}' />
          </Field>
          <Field label="Stream settings JSON">
            <Textarea rows={7} value={form.streamSettings ?? ""} onChange={(e) => setForm({ ...form, streamSettings: e.target.value })} placeholder='{"network":"tcp","security":"tls"}' />
          </Field>
          <Switch checked={form.enabled} onChange={(enabled) => setForm({ ...form, enabled })} label="Outbound enabled" />
          <div className="button-row">
            {editing ? (
              <Button variant="danger" icon={<Trash2 size={16} />} onClick={() => onDelete(editing.id)} disabled={busy}>
                Delete
              </Button>
            ) : null}
            <Button variant="primary" icon={<Save size={16} />} onClick={submit} disabled={busy}>
              Save Outbound
            </Button>
          </div>
        </section>
      </div>
    </div>
  );
}
