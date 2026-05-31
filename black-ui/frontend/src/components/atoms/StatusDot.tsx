type Tone = "green" | "amber" | "red" | "gray" | "cyan";

export function StatusDot({ tone = "gray", label }: { tone?: Tone; label: string }) {
  return (
    <span className="status-dot-wrap">
      <span className={`status-dot status-${tone}`} />
      {label}
    </span>
  );
}
