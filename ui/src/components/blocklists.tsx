import { useState, type ReactNode } from "react";
import { api, CustomList, Firewall, FirewallList } from "../api";
import { Badge, ErrorBox, Spinner } from "./ui";

const LEVELS: { key: FirewallList["level"]; title: string; hint: string; kind: "ok" | "warn" | "err" }[] = [
  { key: "sicher", title: "Sicher", hint: "Fast nie echte Besucher – ohne Bedenken einschalten.", kind: "ok" },
  { key: "mittel", title: "Mittel", hint: "Frische Angreifer der letzten Tage. Selten trifft es eine neu vergebene Adresse.", kind: "warn" },
  { key: "streng", title: "Streng", hint: "Erwischt am meisten, sperrt aber auch harmlose Nutzer.", kind: "err" },
];

const fmtDate = (s?: string) => (s ? new Date(s).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "–");

// slug turns a name into the id part of a custom list.
const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/ä/g, "ae")
    .replace(/ö/g, "oe")
    .replace(/ü/g, "ue")
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 30) || "liste";

type Props = {
  lists: FirewallList[];
  f: Firewall;
  onChange: (f: Firewall) => void;
};

/** Blocklists picks public lists and manages the operator's own ones. */
export function Blocklists({ lists, f, onChange }: Props) {
  const active = new Set(f.lists ?? []);
  const toggle = (id: string, on: boolean) => onChange({ ...f, lists: on ? [...active, id] : [...active].filter((x) => x !== id) });
  const custom = f.customLists ?? [];
  const stored = new Map(lists.map((l) => [l.id, l]));
  const total = [...active].reduce((n, id) => n + (stored.get(id)?.entries ?? 0), 0);

  const row = (l: FirewallList, extra?: ReactNode) => (
    <label key={l.id} className="check" style={{ alignItems: "flex-start" }}>
      <input type="checkbox" checked={active.has(l.id)} onChange={(e) => toggle(l.id, e.target.checked)} />
      <span style={{ flex: 1, minWidth: 0 }}>
        <b>{l.name}</b> {l.desc && <span className="muted small">– {l.desc}</span>}
        <br />
        <span className="muted small" style={{ overflowWrap: "anywhere" }}>
          {l.entries ? `${l.entries.toLocaleString("de-DE")} Einträge, Stand ${fmtDate(l.updated)}` : "noch nicht geladen – wird beim Speichern geladen"} ·{" "}
          <a href={l.source} target="_blank" rel="noreferrer">
            {l.custom ? l.source : "Quelle"}
          </a>
        </span>
      </span>
      {extra}
    </label>
  );

  const remove = (id: string) => onChange({ ...f, customLists: custom.filter((c) => c.id !== id), lists: [...active].filter((x) => x !== id) });
  const add = (c: CustomList) => onChange({ ...f, customLists: [...custom, c], lists: [...active, c.id] });

  return (
    <div className="stack" style={{ gap: 12 }}>
      {active.size > 0 && (
        <span className="small muted">
          {active.size} Listen aktiv, zusammen {total.toLocaleString("de-DE")} Einträge (doppelte zählen einmal).
        </span>
      )}
      {LEVELS.map((lv) => {
        const ls = lists.filter((l) => !l.custom && l.level === lv.key);
        if (ls.length === 0) return null;
        return (
          <div key={lv.key} className="stack" style={{ gap: 6 }}>
            <div className="row" style={{ gap: 8 }}>
              <Badge kind={lv.kind}>{lv.title}</Badge>
              <span className="hint">{lv.hint}</span>
            </div>
            {ls.map((l) => row(l))}
          </div>
        );
      })}
      <div className="stack" style={{ gap: 6 }}>
        <div className="row" style={{ gap: 8 }}>
          <Badge kind="info">Eigene</Badge>
          <span className="hint">Jede Liste mit einer IP oder einem Bereich pro Zeile, z. B. von abuse.ch, deinem eigenen Server oder GitHub.</span>
        </div>
        {lists
          .filter((l) => l.custom)
          .map((l) =>
            row(
              l,
              <button type="button" className="btn sm" onClick={(e) => (e.preventDefault(), remove(l.id))}>
                Entfernen
              </button>,
            ),
          )}
        {custom
          .filter((c) => !stored.has(c.id))
          .map((c) =>
            row(
              { id: c.id, name: c.name, desc: "", source: c.url, license: "", level: "", custom: true, entries: 0 },
              <button type="button" className="btn sm" onClick={(e) => (e.preventDefault(), remove(c.id))}>
                Entfernen
              </button>,
            ),
          )}
        <AddList taken={new Set(custom.map((c) => c.id))} urls={new Set(custom.map((c) => c.url))} onAdd={add} />
      </div>
    </div>
  );
}

function AddList({ taken, urls, onAdd }: { taken: Set<string>; urls: Set<string>; onAdd: (c: CustomList) => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [test, setTest] = useState<{ url: string; entries: number; sample: string[]; limited: boolean } | null>(null);

  const check = async () => {
    setBusy(true);
    setErr(null);
    setTest(null);
    try {
      const r = await api.post<{ entries: number; sample: string[]; limited: boolean }>("/api/firewall/lists/test", { url: url.trim() });
      setTest({ ...r, url: url.trim() });
      if (!name.trim()) {
        try {
          const u = new URL(url.trim());
          const parts = u.pathname.split("/").filter(Boolean);
          const base = parts.pop()?.replace(/\.(txt|netset|ipset|list|csv)$/i, "") ?? "";
          // "5" from …/ipsum/master/levels/5.txt says nothing: name the repo too.
          setName(base.length > 3 ? base : `${(u.hostname.endsWith("githubusercontent.com") && parts[1]) || u.hostname} ${base}`.trim());
        } catch {
          /* keep empty */
        }
      }
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  const add = () => {
    let id = "eigene-" + slug(name);
    for (let i = 2; taken.has(id); i++) id = `eigene-${slug(name)}-${i}`;
    onAdd({ id, name: name.trim(), url: url.trim() });
    setName("");
    setUrl("");
    setTest(null);
  };
  const tested = test?.url === url.trim();

  return (
    <div className="stack" style={{ gap: 6, borderTop: "1px solid var(--border)", paddingTop: 10 }}>
      <div className="inline-fields">
        <input className="mono" style={{ flex: "2 1 260px" }} placeholder="https://example.org/blocklist.txt" value={url} onChange={(e) => setUrl(e.target.value)} />
        <input style={{ flex: "1 1 140px" }} placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="button" className="btn sm" onClick={check} disabled={busy || !url.trim()}>
          {busy ? <Spinner /> : "Testen"}
        </button>
        <button type="button" className="btn sm primary" onClick={add} disabled={!tested || !name.trim() || urls.has(url.trim())}>
          + Hinzufügen
        </button>
      </div>
      {urls.has(url.trim()) && url.trim() && <span className="small muted">Diese Liste ist schon eingetragen.</span>}
      <ErrorBox error={err} />
      {tested && test && (
        <span className="small">
          ✓ {test.entries.toLocaleString("de-DE")} Adressen gefunden{test.limited && " (auf dieses Maximum gekürzt)"}, z. B.{" "}
          <span className="mono">{test.sample.join(", ")}</span>. Private Netze werden immer übersprungen.
        </span>
      )}
      {!tested && <span className="hint">Erst testen, dann hinzufügen. Aktiv wird die Liste mit „Speichern & übernehmen“; danach täglich aktualisiert.</span>}
    </div>
  );
}
