export async function copyText(value: string): Promise<{ ok: boolean; message: string }> {
  if (!value) return { ok: false, message: "Nothing to copy" };
  try {
    await navigator.clipboard.writeText(value);
    return { ok: true, message: "Copied" };
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    try {
      const ok = document.execCommand("copy");
      return ok ? { ok: true, message: "Copied" } : { ok: false, message: "Copy failed" };
    } finally {
      document.body.removeChild(textarea);
    }
  }
}
