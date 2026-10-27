import { Fragment, MouseEvent, ReactNode } from "react";
import { navigate } from "../router";

// A small Markdown renderer for the AI chat: what models actually write
// (headings, lists, tables, code, emphasis, links). It builds React
// elements, never HTML strings, so model output cannot inject markup.

const FENCE = /^\s*(```+|~~~+)\s*([\w+-]*)\s*$/;
const HEADING = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
const RULE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
const LIST = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;
const QUOTE = /^\s{0,3}>\s?(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

const indent = (l: string) => l.length - l.trimStart().length;

function startsBlock(lines: string[], i: number): boolean {
  const l = lines[i];
  return FENCE.test(l) || HEADING.test(l) || RULE.test(l) || LIST.test(l) || QUOTE.test(l) || isTable(lines, i);
}

function isTable(lines: string[], i: number): boolean {
  return lines[i].includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].includes("-");
}

function cells(row: string): string[] {
  let r = row.trim();
  if (r.startsWith("|")) r = r.slice(1);
  if (r.endsWith("|") && !r.endsWith("\\|")) r = r.slice(0, -1);
  return r.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
}

function blocks(lines: string[]): ReactNode[] {
  const out: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const k = out.length;
    if (line.trim() === "") {
      i++;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !(lines[i].trim().startsWith(fence[1]) && lines[i].trim().replace(/[`~]/g, "") === "")) body.push(lines[i++]);
      i++;
      out.push(
        <pre key={k} className="md-code">
          <code>{body.join("\n")}</code>
        </pre>,
      );
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      const level = Math.min(6, h[1].length + 2);
      const Tag = `h${level}` as "h3";
      out.push(<Tag key={k}>{inline(h[2])}</Tag>);
      i++;
      continue;
    }
    if (RULE.test(line)) {
      out.push(<hr key={k} />);
      i++;
      continue;
    }
    if (isTable(lines, i)) {
      const head = cells(line);
      const align = cells(lines[i + 1]).map((c) => (c.startsWith(":") && c.endsWith(":") ? "center" : c.endsWith(":") ? "right" : undefined));
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") rows.push(cells(lines[i++]));
      out.push(
        <div key={k} className="md-table">
          <table>
            <thead>
              <tr>
                {head.map((c, j) => (
                  <th key={j} style={{ textAlign: align[j] }}>
                    {inline(c)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri}>
                  {head.map((_, j) => (
                    <td key={j} style={{ textAlign: align[j] }}>
                      {inline(r[j] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }
    if (QUOTE.test(line)) {
      const body: string[] = [];
      while (i < lines.length && QUOTE.test(lines[i])) body.push(QUOTE.exec(lines[i++])![1]);
      out.push(<blockquote key={k}>{blocks(body)}</blockquote>);
      continue;
    }
    if (LIST.test(line)) {
      const [node, next] = list(lines, i, k);
      out.push(node);
      i = next;
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() !== "" && (para.length === 0 || !startsBlock(lines, i))) para.push(lines[i++].trim());
    out.push(<p key={k}>{joinLines(para)}</p>);
  }
  return out;
}

/** Single line breaks stay line breaks: models format with them. */
function joinLines(ls: string[]): ReactNode[] {
  return ls.map((l, j) => (
    <Fragment key={j}>
      {j > 0 && <br />}
      {inline(l)}
    </Fragment>
  ));
}

function list(lines: string[], start: number, key: number): [ReactNode, number] {
  const first = LIST.exec(lines[start])!;
  const base = first[1].length;
  const ordered = /\d/.test(first[2]);
  const items: string[][] = [];
  let content = base + first[2].length + 1;
  let i = start;
  while (i < lines.length) {
    const l = lines[i];
    const m = LIST.exec(l);
    if (m && m[1].length === base && /\d/.test(m[2]) === ordered) {
      items.push([m[3]]);
      content = base + m[2].length + 1;
      i++;
      continue;
    }
    if (l.trim() === "") {
      const n = lines[i + 1];
      const nm = n !== undefined ? LIST.exec(n) : null;
      if (n !== undefined && n.trim() !== "" && (indent(n) > base || (nm && nm[1].length === base && /\d/.test(nm[2]) === ordered))) {
        items[items.length - 1].push("");
        i++;
        continue;
      }
      break;
    }
    if (indent(l) > base) {
      items[items.length - 1].push(l.slice(Math.min(indent(l), content)));
      i++;
      continue;
    }
    // A wrapped line without indentation still belongs to the item.
    if (!startsBlock(lines, i)) {
      items[items.length - 1].push(l.trim());
      i++;
      continue;
    }
    break;
  }
  const startNum = ordered ? parseInt(first[2], 10) : undefined;
  const children = items.map((it, j) => <li key={j}>{it.length === 1 ? inline(it[0]) : blocks(it)}</li>);
  const node = ordered ? (
    <ol key={key} start={startNum !== 1 ? startNum : undefined}>
      {children}
    </ol>
  ) : (
    <ul key={key}>{children}</ul>
  );
  return [node, i];
}

// Inline: code first (its content stays literal), then emphasis and links.
const INLINE =
  /(`+)([^`][\s\S]*?)\1(?!`)|\*\*(?=\S)([\s\S]*?\S)\*\*|(?<![\w])__(?=\S)([\s\S]*?\S)__(?![\w])|~~(?=\S)([\s\S]*?\S)~~|\*(?=[^\s*])([\s\S]*?[^\s*])\*|(?<![\w])_(?=[^\s_])([\s\S]*?[^\s_])_(?![\w])|\[([^\]]+)\]\(([^)\s]+)\)|(https?:\/\/[^\s<>()]*[^\s<>().,;:!?'"*_])/g;

function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(INLINE)) {
    const at = m.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    last = at + m[0].length;
    if (m[2] !== undefined) out.push(<code key={k++}>{m[2].trim() || m[2]}</code>);
    else if (m[3] !== undefined || m[4] !== undefined) out.push(<strong key={k++}>{inline(m[3] ?? m[4])}</strong>);
    else if (m[5] !== undefined) out.push(<del key={k++}>{inline(m[5])}</del>);
    else if (m[6] !== undefined || m[7] !== undefined) out.push(<em key={k++}>{inline(m[6] ?? m[7])}</em>);
    else if (m[8] !== undefined) out.push(link(m[9], inline(m[8]), k++));
    else out.push(link(m[10], m[10], k++));
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function link(href: string, label: ReactNode, key: number): ReactNode {
  // In-app paths open in the UI; only http(s) leaves it. Anything else
  // (javascript:, data: …) stays plain text.
  if (href.startsWith("/") && !href.startsWith("//")) {
    const go = (e: MouseEvent) => {
      e.preventDefault();
      navigate(href);
    };
    return (
      <a key={key} href={href} onClick={go}>
        {label}
      </a>
    );
  }
  if (!/^https?:\/\//i.test(href)) return <Fragment key={key}>{label}</Fragment>;
  return (
    <a key={key} href={href} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  );
}

/** Markdown renders model text as formatted blocks. */
export function Markdown({ text }: { text: string }) {
  return <div className="md">{blocks(text.replace(/\r\n?/g, "\n").split("\n"))}</div>;
}
