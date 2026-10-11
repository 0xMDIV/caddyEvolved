import { useRef, useState } from "react";
import { IconDownload, IconLock, IconRestore, IconTrash, IconUpload } from "@tabler/icons-react";
import { api, ApiError, BackupEntry, BackupManifest, BackupsResponse, fmtTime, VersionInfo } from "../api";
import { ToggleRow } from "../components/siteform";
import { Badge, ConfirmButton, ErrorBox, PageHead, Spinner, useAction, useLoad, useToast } from "../components/ui";

const KIND: Record<BackupEntry["kind"], { label: string; kind: "ok" | "info" | "warn" }> = {
  manual: { label: "manuell", kind: "info" },
  auto: { label: "automatisch", kind: "ok" },
  "pre-restore": { label: "vor Wiederherstellung", kind: "warn" },
};

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** After a restore the daemon restarts; wait for it, then reload the app. */
async function waitForRestart() {
  await new Promise((r) => setTimeout(r, 2500));
  for (let i = 0; i < 40; i++) {
    try {
      await api.get<VersionInfo>("/api/version");
      window.location.reload();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  window.location.reload();
}

export default function Backup() {
  const list = useLoad(() => api.get<BackupsResponse>("/api/backups"));
  const toast = useToast();
  const { busy, run } = useAction();

  const [certs, setCerts] = useState(false);
  const [encrypt, setEncrypt] = useState(false);
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [createErr, setCreateErr] = useState<unknown>(null);

  async function create() {
    setCreateErr(null);
    if (encrypt && (pass.length < 8 || pass !== pass2)) {
      setCreateErr(new Error(pass.length < 8 ? "Passwort: mindestens 8 Zeichen" : "Die Passwörter stimmen nicht überein"));
      return;
    }
    try {
      const r = await api.post<{ backup: BackupEntry }>("/api/backups", { certs, passphrase: encrypt ? pass : "" });
      toast("ok", "Backup erstellt – Download startet");
      setPass("");
      setPass2("");
      list.reload();
      window.location.href = "/api/backups/" + encodeURIComponent(r.backup.name);
    } catch (e) {
      setCreateErr(e);
    }
  }

  const st = list.data?.settings;
  return (
    <>
      <PageHead title="Backup" sub="Sichert Sites, Access Lists, Einstellungen, Zugangsdaten und auf Wunsch die Zertifikate – und stellt sie wieder her." />
      <ErrorBox error={list.error} />
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card stack">
          <h2 style={{ margin: 0 }}>Backup erstellen</h2>
          <ToggleRow checked={certs} onChange={setCerts} label="Zertifikate mitsichern" hint="Zertifikate, Schlüssel, ACME-Konten und die interne CA. Ohne holt Caddy sie nach einer Wiederherstellung neu." />
          <ToggleRow
            checked={encrypt}
            onChange={setEncrypt}
            label="Mit Passwort verschlüsseln"
            hint="Empfohlen: Das Backup enthält Zugangsdaten (z. B. DNS-API-Token) und den Passwort-Hash der WebUI."
          />
          {encrypt && (
            <div className="form-grid">
              <label className="field">
                Passwort
                <input type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
              </label>
              <label className="field">
                Wiederholen
                <input type="password" autoComplete="new-password" value={pass2} onChange={(e) => setPass2(e.target.value)} />
              </label>
              <span className="hint full">Ohne dieses Passwort lässt sich das Backup nicht wiederherstellen – es gibt keinen Weg zurück.</span>
            </div>
          )}
          <ErrorBox error={createErr} />
          <button className="btn primary" style={{ alignSelf: "flex-start" }} disabled={busy !== null} onClick={() => run("create", create)}>
            {busy === "create" ? <Spinner /> : <IconDownload size={16} />} Backup erstellen und herunterladen
          </button>
        </div>

        <AutoBackupCard settings={st} lastAuto={list.data?.lastAuto} onSaved={list.reload} />
      </div>

      <RestoreCard />

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Auf dem Server gespeichert</h2>
        <p className="small muted" style={{ marginTop: 0 }}>
          Ablage: <span className="mono">{list.data?.dir}</span>. Vor jeder Wiederherstellung wird der aktuelle Stand hier automatisch gesichert.
        </p>
        {list.loading && !list.data ? (
          <Spinner />
        ) : (list.data?.backups ?? []).length === 0 ? (
          <div className="empty">Noch keine Backups.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Erstellt</th>
                  <th>Art</th>
                  <th>Größe</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {list.data!.backups.map((b) => (
                  <StoredRow key={b.name} b={b} onChange={list.reload} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function StoredRow({ b, onChange }: { b: BackupEntry; onChange: () => void }) {
  const [restoring, setRestoring] = useState(false);
  return (
    <>
      <tr>
        <td>
          <div>{fmtTime(b.createdAt)}</div>
          <div className="small muted mono wrap-any">{b.name}</div>
        </td>
        <td>
          <div className="chips">
            <Badge kind={KIND[b.kind].kind}>{KIND[b.kind].label}</Badge>
            {b.encrypted && (
              <Badge>
                <IconLock size={12} /> verschlüsselt
              </Badge>
            )}
          </div>
        </td>
        <td className="small">{fmtSize(b.size)}</td>
        <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
          <span className="row" style={{ justifyContent: "flex-end" }}>
            <a className="btn ghost sm" href={"/api/backups/" + encodeURIComponent(b.name)} title="Herunterladen" aria-label="Herunterladen">
              <IconDownload size={16} />
            </a>
            <button className="btn ghost sm" onClick={() => setRestoring((v) => !v)}>
              <IconRestore size={16} /> Wiederherstellen
            </button>
            <ConfirmButton
              confirmText="Löschen?"
              onConfirm={async () => {
                await api.del(`/api/backups/${encodeURIComponent(b.name)}`);
                onChange();
              }}
            >
              <IconTrash size={14} />
            </ConfirmButton>
          </span>
        </td>
      </tr>
      {restoring && (
        <tr>
          <td colSpan={4}>
            <RestoreFlow source={{ name: b.name }} encrypted={b.encrypted} />
          </td>
        </tr>
      )}
    </>
  );
}

function AutoBackupCard({ settings, lastAuto, onSaved }: { settings?: { daily: boolean; keep: number; certs: boolean }; lastAuto?: string; onSaved: () => void }) {
  const [draft, setDraft] = useState<{ daily: boolean; keep: number; certs: boolean } | null>(null);
  const v = draft ?? settings ?? { daily: false, keep: 7, certs: false };
  const toast = useToast();
  const [err, setErr] = useState<unknown>(null);
  async function save() {
    try {
      await api.put("/api/backups/settings", v);
      toast("ok", "Gespeichert");
      setDraft(null);
      onSaved();
    } catch (e) {
      setErr(e);
    }
  }
  return (
    <div className="card stack">
      <h2 style={{ margin: 0 }}>Automatische Sicherung</h2>
      <ToggleRow checked={v.daily} onChange={(d) => setDraft({ ...v, daily: d })} label="Täglich sichern" hint={`Letzte: ${fmtTime(lastAuto)}`} />
      <ToggleRow checked={v.certs} onChange={(c) => setDraft({ ...v, certs: c })} label="Zertifikate mitsichern" disabled={!v.daily} />
      <label className="field" style={{ maxWidth: 220 }}>
        Aufbewahren
        <input type="number" min={1} max={365} value={v.keep} onChange={(e) => setDraft({ ...v, keep: Number(e.target.value) })} />
        <span className="hint">neueste automatische Backups; ältere werden gelöscht</span>
      </label>
      <p className="small muted" style={{ margin: 0 }}>
        Automatische Backups liegen unverschlüsselt auf dem Server (nur root lesbar). Für eine Kopie außerhalb: herunterladen oder per{" "}
        <span className="mono">caddyevolved backup --encrypt --out …</span> wegsichern.
      </p>
      <ErrorBox error={err} />
      <button className="btn" style={{ alignSelf: "flex-start" }} disabled={!draft} onClick={save}>
        Speichern
      </button>
    </div>
  );
}

function RestoreCard() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  return (
    <div className="card stack" style={{ marginTop: 16 }}>
      <h2 style={{ margin: 0 }}>Aus Datei wiederherstellen</h2>
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <input
          ref={fileRef}
          type="file"
          accept=".gz,.cevbak,application/gzip,application/octet-stream"
          style={{ display: "none" }}
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <button className="btn" onClick={() => fileRef.current?.click()}>
          <IconUpload size={16} /> Backup-Datei wählen
        </button>
        {file && (
          <span className="small mono">
            {file.name} ({fmtSize(file.size)})
          </span>
        )}
      </div>
      {file && <RestoreFlow key={file.name + file.size} source={{ file }} encrypted={file.name.endsWith(".cevbak")} />}
    </div>
  );
}

/** Preview → confirm → restore → wait for the restart. */
function RestoreFlow({ source, encrypted }: { source: { name?: string; file?: File }; encrypted: boolean }) {
  const [pass, setPass] = useState("");
  const [needPass, setNeedPass] = useState(encrypted);
  const [preview, setPreview] = useState<{ manifest: BackupManifest; files: string[] } | null>(null);
  const [certs, setCerts] = useState(false);
  const [phase, setPhase] = useState<"" | "preview" | "restore" | "restart">("");
  const [err, setErr] = useState<unknown>(null);

  const url = (base: string) => base + (source.name ? `?name=${encodeURIComponent(source.name)}` : "");
  const send = <T,>(path: string) =>
    api.upload<T>(path, source.file ?? new Blob([]), pass ? { "X-Backup-Passphrase": pass } : undefined);

  async function loadPreview() {
    setErr(null);
    setPhase("preview");
    try {
      const p = await send<{ manifest: BackupManifest; files: string[] }>(url("/api/restore/preview"));
      setPreview(p);
      setCerts(p.manifest.certs);
    } catch (e) {
      if (e instanceof ApiError && e.code === "passphrase") setNeedPass(true);
      setErr(e);
    } finally {
      setPhase("");
    }
  }

  async function restore() {
    setErr(null);
    setPhase("restore");
    try {
      const r = await send<{ restarting: boolean; safety: string }>(url("/api/restore") + (source.name ? "&" : "?") + (certs ? "certs=1" : "certs=0"));
      if (r.restarting) {
        setPhase("restart");
        await waitForRestart();
      } else {
        window.location.reload();
      }
    } catch (e) {
      setErr(e);
      setPhase("");
    }
  }

  const m = preview?.manifest;
  return (
    <div className="stack" style={{ gap: 10 }}>
      {needPass && !preview && (
        <label className="field" style={{ maxWidth: 320 }}>
          Passwort des Backups
          <input type="password" autoComplete="off" value={pass} onChange={(e) => setPass(e.target.value)} />
        </label>
      )}
      {!preview && (
        <button className="btn" style={{ alignSelf: "flex-start" }} disabled={phase !== "" || (needPass && !pass)} onClick={loadPreview}>
          {phase === "preview" && <Spinner />} Inhalt prüfen
        </button>
      )}
      {m && (
        <div className="restore-preview">
          <div>
            <b>Stand vom {fmtTime(m.createdAt)}</b> · {m.host} · caddyEvolved {m.version || "?"}
          </div>
          <div className="small">
            {m.sites} Sites · {m.files} Dateien {m.secrets && "· mit Zugangsdaten"} {m.certs && "· mit Zertifikaten"} {m.encrypted && "· verschlüsselt"}
          </div>
          {m.certs && <ToggleRow checked={certs} onChange={setCerts} label="Zertifikate auch wiederherstellen" />}
          <div className="alert warn" style={{ margin: 0 }}>
            Ersetzt die aktuelle Konfiguration. Sites, die es im Backup nicht gibt, werden entfernt. Der jetzige Stand wird vorher automatisch gesichert; lehnt
            Caddy die Konfiguration ab, kommt er sofort zurück. Danach startet die WebUI neu – evtl. neu anmelden.
          </div>
          <ConfirmButton className="btn primary" confirmText="Jetzt wiederherstellen?" disabled={phase !== ""} onConfirm={restore}>
            {phase === "restore" || phase === "restart" ? <Spinner /> : <IconRestore size={16} />}{" "}
            {phase === "restart" ? "Startet neu …" : "Wiederherstellen"}
          </ConfirmButton>
        </div>
      )}
      <ErrorBox error={err} />
    </div>
  );
}
