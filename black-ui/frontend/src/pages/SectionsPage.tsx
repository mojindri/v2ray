import { useEffect, useState } from "react";
import { Save } from "lucide-react";
import type { CapabilityMap, ConfigSection } from "../lib/types";
import { Badge } from "../components/atoms/Badge";
import { Button } from "../components/atoms/Button";
import { Textarea } from "../components/atoms/Input";
import { Switch } from "../components/atoms/Switch";
import { Field } from "../components/molecules/Field";

export function SectionsPage({
  sections,
  capabilities,
  busy,
  onSave
}: {
  sections: ConfigSection[];
  capabilities: CapabilityMap | null;
  busy: boolean;
  onSave: (name: string, enabled: boolean, value: string) => void;
}) {
  const [selected, setSelected] = useState<ConfigSection | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [value, setValue] = useState("");
  const notes = new Map((capabilities?.config ?? []).map((item) => [item.key, item]));

  useEffect(() => {
    if (!selected && sections.length > 0) setSelected(sections[0]);
  }, [sections, selected]);

  useEffect(() => {
    if (!selected) return;
    setEnabled(selected.enabled);
    setValue(selected.value);
  }, [selected]);

  return (
    <div className="page">
      <div className="page-title">
        <h1>Config Sections</h1>
        <p>Raw validated Blackwire JSON for routing, DNS, TUN, metrics, profile, and API coverage.</p>
      </div>
      <div className="two-column">
        <section className="work-panel">
          <h2>Sections</h2>
          <div className="stack-list">
            {sections.map((section) => {
              const cap = notes.get(section.name);
              return (
                <button className="stack-row" key={section.name} onClick={() => setSelected(section)} type="button">
                  <span>
                    <strong>{section.name}</strong>
                    <small>{cap?.notes ?? "Blackwire native config section"}</small>
                  </span>
                  <Badge tone={section.enabled ? "green" : "gray"}>{cap?.status ?? "supported"}</Badge>
                </button>
              );
            })}
          </div>
        </section>
        <section className="work-panel editor-panel">
          <h2>{selected ? selected.name : "Select section"}</h2>
          {selected ? (
            <>
              <Switch checked={enabled} onChange={setEnabled} label="Include section in generated config" />
              <Field label="JSON value">
                <Textarea rows={18} value={value} onChange={(e) => setValue(e.target.value)} />
              </Field>
              <Button variant="primary" icon={<Save size={16} />} onClick={() => onSave(selected.name, enabled, value)} disabled={busy}>
                Save Section
              </Button>
            </>
          ) : null}
        </section>
      </div>
    </div>
  );
}
