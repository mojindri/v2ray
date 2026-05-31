type Tone = "green" | "amber" | "red" | "gray" | "cyan";

export function Badge({ children, tone = "gray" }: { children: string; tone?: Tone }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
