import { cloneElement, isValidElement, useId } from "react";
import type { ReactElement, ReactNode } from "react";

export function Field({
  label,
  hint,
  children
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  const generatedId = useId();
  let controlId: string | undefined;
  let content = children;

  if (isValidElement(children)) {
    const child = children as ReactElement<{ id?: string }>;
    controlId = child.props.id ?? generatedId;
    content = cloneElement(child, { id: controlId });
  }

  return (
    <div className="field">
      <label className="field-label" htmlFor={controlId}>
        {label}
      </label>
      {content}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </div>
  );
}
