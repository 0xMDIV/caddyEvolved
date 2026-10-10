import { useEffect, useState } from "react";
import {
  api,
  BINARY_CHANGED,
  DEFENDER_RANGES,
  defaultDefender,
  defaultRateLimit,
  defaultWaf,
  PluginsResponse,
  SiteDefender,
  SiteRateLimit,
  SiteWaf,
} from "../api";
import { Switch } from "./ui";

/** Plugin ids whose site-level sections the UI offers. */
export const FEATURE_PLUGINS = { waf: "coraza", defender: "caddy-defender", rateLimit: "caddy-ratelimit" } as const;

/** Which catalog plugins are compiled into the running binary, by id. */
export function useCompiledPlugins(): Record<string, boolean> {
  const [compiled, setCompiled] = useState<Record<string, boolean>>({});
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await api.get<PluginsResponse>("/api/plugins");
        const m: Record<string, boolean> = {};
        for (const p of r.plugins ?? []) m[p.id] = p.detected;
        if (alive) setCompiled(m);
      } catch {
        /* sections stay hidden */
      }
    };
    load();
    window.addEventListener(BINARY_CHANGED, load);
    return () => {
      alive = false;
      window.removeEventListener(BINARY_CHANGED, load);
    };
  }, []);
  return compiled;
}

export function WafFields({ value, onChange }: { value?: SiteWaf; onChange: (v: SiteWaf | undefined) => void }) {
  const v = value ?? { ...defaultWaf(), enabled: false };
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="WAF aktiv" />
        WAF <span className="hint">(Coraza + OWASP Core Rule Set)</span>
      </div>
      {v.enabled && (
        <div className="inline-fields">
          <label className="check">
            <input type="radio" checked={v.mode === "block"} onChange={() => onChange({ ...v, mode: "block" })} /> Blockieren
          </label>
          <label className="check">
            <input type="radio" checked={v.mode === "detect"} onChange={() => onChange({ ...v, mode: "detect" })} /> Nur erkennen (Log)
          </label>
          <span className="hint">Neue Sites erst mit „Nur erkennen“ testen – CRS blockt sonst auch Fehlalarme.</span>
        </div>
      )}
    </div>
  );
}

export function DefenderFields({ value, onChange }: { value?: SiteDefender; onChange: (v: SiteDefender | undefined) => void }) {
  const v = value ?? { ...defaultDefender(), enabled: false };
  const toggleRange = (r: string, on: boolean) =>
    onChange({ ...v, ranges: on ? [...v.ranges.filter((x) => x !== r), r] : v.ranges.filter((x) => x !== r) });
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="Bot-Abwehr aktiv" />
        Bot-Abwehr <span className="hint">(KI-Crawler und Cloud-Netze aussperren)</span>
      </div>
      {v.enabled && (
        <>
          <label className="field">
            Reaktion
            <select value={v.responder} onChange={(e) => onChange({ ...v, responder: e.target.value as SiteDefender["responder"] })}>
              <option value="block">Blockieren (403)</option>
              <option value="tarpit">Tarpit (extrem langsam antworten)</option>
              <option value="garbage">Müll-Daten ausliefern</option>
              <option value="drop">Verbindung kappen</option>
            </select>
          </label>
          <div className="check-grid">
            {DEFENDER_RANGES.map((r) => (
              <label key={r} className="check small">
                <input type="checkbox" checked={v.ranges.includes(r)} onChange={(e) => toggleRange(r, e.target.checked)} /> {r}
              </label>
            ))}
          </div>
          {v.ranges.length === 0 && <span className="hint">Mindestens einen Bereich wählen.</span>}
        </>
      )}
    </div>
  );
}

export function RateLimitFields({ value, onChange }: { value?: SiteRateLimit; onChange: (v: SiteRateLimit | undefined) => void }) {
  const v = value ?? { ...defaultRateLimit(), enabled: false };
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="Rate Limit aktiv" />
        Rate Limit <span className="hint">(pro Client-IP)</span>
      </div>
      {v.enabled && (
        <div className="inline-fields">
          <input
            type="number"
            min={1}
            style={{ width: 100 }}
            value={v.events}
            onChange={(e) => onChange({ ...v, events: Math.max(1, Number(e.target.value) || 1) })}
          />
          <span>Anfragen pro</span>
          <select value={v.window} onChange={(e) => onChange({ ...v, window: e.target.value })}>
            {["10s", "30s", "1m", "5m", "1h"].map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
            {!["10s", "30s", "1m", "5m", "1h"].includes(v.window) && <option value={v.window}>{v.window}</option>}
          </select>
          <span className="hint">Darüber antwortet Caddy mit 429.</span>
        </div>
      )}
    </div>
  );
}
