import { useState } from "react";
import { AccessList, AccessListsResponse, api } from "../api";
import { navigate } from "../router";
import { Badge, ConfirmButton, ErrorBox, PageHead, Spinner, useLoad, useToast } from "../components/ui";

const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

function summary(a: AccessList): string[] {
  const out: string[] = [];
  if ((a.allow ?? []).length) out.push(`erlaubt: ${(a.allow ?? []).join(", ")}`);
  if ((a.deny ?? []).length) out.push(`gesperrt: ${(a.deny ?? []).join(", ")}`);
  if ((a.allowCountries ?? []).length) out.push(`Länder erlaubt: ${(a.allowCountries ?? []).join(" ")}`);
  if ((a.denyCountries ?? []).length) out.push(`Länder gesperrt: ${(a.denyCountries ?? []).join(" ")}`);
  return out;
}

export default function AccessLists() {
  const list = useLoad(() => api.get<AccessListsResponse>("/api/access-lists"));
  const [editing, setEditing] = useState<{ acl: AccessList | null } | null>(null);
  const [delErr, setDelErr] = useState<unknown>(null);
  const toast = useToast();

  async function remove(a: AccessList) {
    setDelErr(null);
    try {
      const r = await api.del<{ reloaded: boolean }>(`/api/access-lists/${encodeURIComponent(a.id)}`);
      toast("ok", r.reloaded ? `${a.name} gelöscht, Caddy neu geladen` : `${a.name} gelöscht`);
      list.reload();
    } catch (e) {
      setDelErr(e);
    }
  }

  if (editing) {
    return (
      <ACLEditor
        initial={editing.acl}
        geoAvailable={list.data?.geoAvailable ?? false}
        onDone={(saved) => {
          setEditing(null);
          if (saved) list.reload();
        }}
      />
    );
  }

  const acls = list.data?.accessLists ?? [];
  return (
    <>
      <PageHead
        title="Access Lists"
        sub="Wer eine Site erreichen darf: IP-Bereiche, Länder und Benutzer mit Passwort. Einer Site zuweisen unter Sites → Bearbeiten."
      >
        <button className="btn primary" onClick={() => setEditing({ acl: null })}>
          + Neue Access List
        </button>
      </PageHead>
      <ErrorBox error={list.error} />
      <ErrorBox error={delErr} />
      <div className="card">
        {list.loading && !list.data ? (
          <div className="empty">
            <Spinner />
          </div>
        ) : acls.length === 0 ? (
          <div className="empty">
            Noch keine Access Lists. Typische erste Liste: „Nur LAN“ mit <code>private_ranges</code>, damit interne Dienste nicht aus dem
            Internet erreichbar sind.
            <div style={{ marginTop: 12 }}>
              <button className="btn primary" onClick={() => setEditing({ acl: null })}>
                Erste Access List anlegen
              </button>
            </div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Regeln</th>
                  <th>Benutzer</th>
                  <th>Benutzt von</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {acls.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{a.name}</div>
                      <div className="small muted mono">{a.id}</div>
                    </td>
                    <td className="small">
                      {summary(a).length === 0 ? <span className="muted">nur Login</span> : summary(a).map((l, i) => <div key={i}>{l}</div>)}
                      {a.needsGeo && !list.data?.geoAvailable && (
                        <div style={{ marginTop: 4 }}>
                          <Badge kind="warn">Geo-Plugin fehlt</Badge>
                        </div>
                      )}
                    </td>
                    <td>
                      <div className="chips">
                        {(a.users ?? []).map((u) => (
                          <Badge key={u.username} kind="info">
                            {u.username}
                          </Badge>
                        ))}
                        {(a.users ?? []).length === 0 && <span className="muted small">–</span>}
                      </div>
                    </td>
                    <td>
                      <div className="chips">
                        {(a.usedBy ?? []).map((s) => (
                          <a
                            key={s}
                            href="/sites"
                            className="badge"
                            onClick={(e) => {
                              e.preventDefault();
                              navigate("/sites");
                            }}
                          >
                            {s}
                          </a>
                        ))}
                        {(a.usedBy ?? []).length === 0 && <span className="muted small">keiner Site zugewiesen</span>}
                      </div>
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <span className="row" style={{ justifyContent: "flex-end" }}>
                        <button className="btn sm" onClick={() => setEditing({ acl: a })}>
                          Bearbeiten
                        </button>
                        <ConfirmButton onConfirm={() => remove(a)} confirmText="Löschen?">
                          Löschen
                        </ConfirmButton>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

interface UserRow {
  username: string;
  password: string;
  hasPassword: boolean;
}

function ACLEditor({ initial, geoAvailable, onDone }: { initial: AccessList | null; geoAvailable: boolean; onDone: (saved: boolean) => void }) {
  const isNew = initial === null;
  const [name, setName] = useState(initial?.name ?? "");
  const [allow, setAllow] = useState((initial?.allow ?? []).join("\n"));
  const [deny, setDeny] = useState((initial?.deny ?? []).join("\n"));
  const [allowCountries, setAllowCountries] = useState((initial?.allowCountries ?? []).join(" "));
  const [denyCountries, setDenyCountries] = useState((initial?.denyCountries ?? []).join(" "));
  const [geoDb, setGeoDb] = useState(initial?.geoDb || "/var/lib/caddyevolved/GeoLite2-Country.mmdb");
  const [users, setUsers] = useState<UserRow[]>((initial?.users ?? []).map((u) => ({ username: u.username, password: "", hasPassword: u.hasPassword })));
  const [err, setErr] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const hadCountries = (initial?.allowCountries ?? []).length + (initial?.denyCountries ?? []).length > 0;
  const showGeo = geoAvailable || hadCountries;
  const countries = (s: string) =>
    s
      .split(/[\s,]+/)
      .map((x) => x.trim().toUpperCase())
      .filter(Boolean);

  function setUser(i: number, patch: Partial<UserRow>) {
    setUsers((v) => v.map((u, j) => (j === i ? { ...u, ...patch } : u)));
  }

  async function save() {
    setSaving(true);
    setErr(null);
    const ac = showGeo ? countries(allowCountries) : [];
    const dc = showGeo ? countries(denyCountries) : [];
    const body = {
      name: name.trim(),
      allow: lines(allow),
      deny: lines(deny),
      allowCountries: ac,
      denyCountries: dc,
      geoDb: ac.length + dc.length > 0 ? geoDb.trim() : "",
      users: users.filter((u) => u.username.trim()).map((u) => ({ username: u.username.trim(), password: u.password })),
    };
    try {
      const r = isNew
        ? await api.post<{ reloaded: boolean }>("/api/access-lists", body)
        : await api.put<{ reloaded: boolean }>(`/api/access-lists/${encodeURIComponent(initial!.id)}`, body);
      toast("ok", r.reloaded ? "Gespeichert und Caddy neu geladen" : "Gespeichert");
      onDone(true);
    } catch (e) {
      setErr(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHead title={isNew ? "Neue Access List" : `Access List ${initial!.name}`}>
        <button className="btn" onClick={() => onDone(false)}>
          Abbrechen
        </button>
        <button className="btn primary" onClick={save} disabled={saving || !name.trim()}>
          {saving && <Spinner />} Speichern & anwenden
        </button>
      </PageHead>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card stack">
          <label className="field">
            Name
            <input value={name} placeholder="z. B. Nur LAN" onChange={(e) => setName(e.target.value)} />
          </label>
          <div className="form-grid">
            <label className="field">
              Erlaubte IPs / Netze
              <textarea rows={4} value={allow} placeholder={"private_ranges\n203.0.113.0/24"} onChange={(e) => setAllow(e.target.value)} />
              <span className="hint">Leer = alle erlaubt. Sonst kommen nur diese durch. „private_ranges“ = LAN + localhost.</span>
            </label>
            <label className="field">
              Gesperrte IPs / Netze
              <textarea rows={4} value={deny} placeholder={"192.168.10.99\n198.51.100.0/24"} onChange={(e) => setDeny(e.target.value)} />
              <span className="hint">Wird zuerst geprüft, gewinnt also gegen „erlaubt“.</span>
            </label>
          </div>

          {showGeo ? (
            <div className="feature">
              <div className="feature-head">
                Länder <span className="hint">(MaxMind GeoLite2)</span>
                {!geoAvailable && <Badge kind="warn">Geo-Plugin nicht in der Binary</Badge>}
              </div>
              <div className="form-grid">
                <label className="field">
                  Nur diese Länder erlauben
                  <input value={allowCountries} placeholder="DE AT CH" onChange={(e) => setAllowCountries(e.target.value)} />
                </label>
                <label className="field">
                  Diese Länder sperren
                  <input value={denyCountries} placeholder="RU CN" onChange={(e) => setDenyCountries(e.target.value)} />
                </label>
                <label className="field full">
                  Pfad zur GeoLite2-Country.mmdb
                  <input value={geoDb} onChange={(e) => setGeoDb(e.target.value)} />
                  <span className="hint">Datei muss auf dem Server liegen und für caddy lesbar sein.</span>
                </label>
              </div>
            </div>
          ) : (
            <div className="small muted">
              Länder-Regeln brauchen das Plugin „Geo-Blocking (MaxMind)“ –{" "}
              <a
                href="/build"
                onClick={(e) => {
                  e.preventDefault();
                  navigate("/build");
                }}
              >
                unter Plugins & Build einbauen
              </a>
              .
            </div>
          )}

          <div className="feature">
            <div className="feature-head">
              Benutzer <span className="hint">(Basic Auth – Browser fragt nach Login)</span>
            </div>
            {users.length === 0 && <div className="small muted">Keine Benutzer – nur die IP-/Länderregeln gelten.</div>}
            {users.map((u, i) => (
              <div key={i} className="inline-fields">
                <input value={u.username} placeholder="Benutzername" onChange={(e) => setUser(i, { username: e.target.value })} />
                <input
                  type="password"
                  autoComplete="new-password"
                  value={u.password}
                  placeholder={u.hasPassword ? "unverändert lassen" : "Passwort (min. 8 Zeichen)"}
                  onChange={(e) => setUser(i, { password: e.target.value })}
                />
                {u.hasPassword && !u.password && <Badge kind="ok">Passwort gesetzt</Badge>}
                <button className="btn sm" onClick={() => setUsers((v) => v.filter((_, j) => j !== i))}>
                  Entfernen
                </button>
              </div>
            ))}
            <div>
              <button className="btn sm" onClick={() => setUsers((v) => [...v, { username: "", password: "", hasPassword: false }])}>
                + Benutzer
              </button>
            </div>
          </div>
          <ErrorBox error={err} />
        </div>

        <div className="card">
          <h2>So wird geprüft</h2>
          <ol className="small" style={{ paddingLeft: 18, margin: 0, lineHeight: 1.7 }}>
            <li>Gesperrte IP → 403</li>
            <li>Nicht in „erlaubt“ (falls gesetzt) → 403</li>
            <li>Land nicht erlaubt / gesperrt → 403</li>
            <li>Benutzer gesetzt → Login-Abfrage</li>
            <li>Erst dann geht die Anfrage an die Site.</li>
          </ol>
          <p className="small muted">
            Hinter einem weiteren Proxy (z. B. Cloudflare) sieht Caddy dessen IP. Dann im Caddyfile unter <code>servers</code> die{" "}
            <code>trusted_proxies</code> setzen, sonst greifen IP-Regeln auf die falsche Adresse.
          </p>
        </div>
      </div>
    </>
  );
}
