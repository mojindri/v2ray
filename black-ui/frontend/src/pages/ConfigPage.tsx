import { useEffect, useState } from "react";
import { CheckCircle2, FileJson, Save, Upload, Zap } from "lucide-react";
import { api } from "../lib/api";
import { Button } from "../components/atoms/Button";

export function ConfigPage({
  busy,
  onValidate,
  onWrite,
  onApply,
  onImport
}: {
  busy: boolean;
  onValidate: () => void;
  onWrite: () => void;
  onApply: () => void;
  onImport: (value: unknown) => void;
}) {
  const [preview, setPreview] = useState("Loading preview...");
  const [importText, setImportText] = useState("");
  useEffect(() => {
    api
      .configPreview()
      .then((value) => setPreview(JSON.stringify(value, null, 2)))
      .catch((error: Error) => setPreview(error.message));
  }, []);

  const submitImport = () => {
    try {
      onImport(JSON.parse(importText));
    } catch (error) {
      window.alert(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <div className="page">
      <div className="page-title">
        <h1>Config</h1>
        <p>Generated Blackwire config from panel data.</p>
      </div>
      <section className="work-panel config-panel">
        <div className="panel-toolbar">
          <h2>Preview</h2>
          <div className="button-row">
            <Button variant="secondary" icon={<CheckCircle2 size={16} />} onClick={onValidate} disabled={busy}>
              Validate
            </Button>
            <Button variant="secondary" icon={<Save size={16} />} onClick={onWrite} disabled={busy}>
              Write
            </Button>
            <Button variant="primary" icon={<Zap size={16} />} onClick={onApply} disabled={busy}>
              Apply
            </Button>
          </div>
        </div>
        <pre className="config-code"><FileJson size={18} />{preview}</pre>
      </section>
      <section className="work-panel config-panel">
        <div className="panel-toolbar">
          <h2>Import Blackwire Config</h2>
          <Button
            variant="secondary"
            icon={<Upload size={16} />}
            onClick={submitImport}
            disabled={busy || !importText.trim()}
          >
            Import
          </Button>
        </div>
        <textarea
          className="input textarea"
          rows={12}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder='{"inbounds":[],"outbounds":[{"tag":"freedom","protocol":"freedom"}]}'
        />
      </section>
    </div>
  );
}
