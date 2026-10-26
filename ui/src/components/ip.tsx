import { useEffect, useState } from "react";
import { IconCheck, IconCopy, IconWorldSearch } from "@tabler/icons-react";
import { api } from "../api";
import { countryName } from "./countries";

/** Country and network of an IP, as the API returns it in "ipGeo". */
export interface IPGeo {
  country?: string;
  asn?: number;
  asnOrg?: string;
}
export type IPGeoMap = Record<string, IPGeo>;

export const DEFAULT_LOOKUP = "https://ipinfo.io/{ip}";

export const LOOKUP_PRESETS: { label: string; url: string }[] = [
  { label: "ipinfo", url: "https://ipinfo.io/{ip}" },
  { label: "AbuseIPDB", url: "https://www.abuseipdb.com/check/{ip}" },
  { label: "who.is", url: "https://who.is/whois-ip/ip-address/{ip}" },
  { label: "bgp.he.net", url: "https://bgp.he.net/ip/{ip}" },
];

// The lookup URL is loaded once per page load and shared by every IPCell.
let lookupUrl: string | null = null;
let lookupLoad: Promise<string> | null = null;
const lookupListeners = new Set<(u: string) => void>();

/** setLookupUrl updates every IPCell after the setting was saved. */
export function setLookupUrl(u: string) {
  lookupUrl = u;
  lookupListeners.forEach((fn) => fn(u));
}

export function useLookupUrl(): string {
  const [url, setUrl] = useState(lookupUrl ?? DEFAULT_LOOKUP);
  useEffect(() => {
    lookupListeners.add(setUrl);
    if (lookupUrl === null) {
      lookupLoad ??= api
        .get<{ settings: { lookupUrl?: string } }>("/api/logging")
        .then((r) => r.settings.lookupUrl || DEFAULT_LOOKUP)
        .catch(() => DEFAULT_LOOKUP);
      lookupLoad.then(setLookupUrl);
    }
    return () => {
      lookupListeners.delete(setUrl);
    };
  }, []);
  return url;
}

/** Regional indicator letters render as the country's flag. */
export function flag(cc: string): string {
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Plain-HTTP LAN access has no clipboard API.
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

/** IPCell shows an IP with its country, a copy button and the lookup link. */
export function IPCell({ ip, geo, onFilter }: { ip: string; geo?: IPGeo; onFilter?: () => void }) {
  const url = useLookupUrl();
  const [copied, setCopied] = useState(false);
  if (!ip) return <span className="muted">–</span>;
  const net = geo?.asnOrg ? `AS${geo.asn} ${geo.asnOrg}` : "";
  return (
    <span className="ip-cell" onClick={(e) => e.stopPropagation()}>
      {geo?.country && (
        <span className="ip-country" title={[countryName(geo.country), net].filter(Boolean).join(" · ")}>
          {flag(geo.country)} {geo.country}
        </span>
      )}
      {onFilter ? (
        <button className="link-btn mono" title={net ? `${net} – nach dieser IP filtern` : "Nach dieser IP filtern"} onClick={onFilter}>
          {ip}
        </button>
      ) : (
        <span className="mono" title={net || undefined}>
          {ip}
        </span>
      )}
      <button
        className="icon-btn"
        title="IP kopieren"
        aria-label="IP kopieren"
        onClick={() => {
          copy(ip).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
      </button>
      <a className="icon-btn" title="IP prüfen" aria-label="IP prüfen" href={url.replace("{ip}", encodeURIComponent(ip))} target="_blank" rel="noopener noreferrer">
        <IconWorldSearch size={14} />
      </a>
    </span>
  );
}

/**
 * Redacted blurs the shortened part of secrets ("abcd******") until clicked.
 * The full value is not known to the UI; the click only shows the prefix.
 */
export function Redacted({ text }: { text: string }) {
  const [shown, setShown] = useState(false);
  if (!text.includes("******")) return <>{text}</>;
  const parts = text.split(/([^&?=\s"]{0,4}\*{6})/);
  return (
    <>
      {parts.map((p, i) =>
        p.endsWith("******") ? (
          <span
            key={i}
            className={shown ? "redacted shown" : "redacted"}
            title={shown ? "Gekürzt – der volle Wert wird nicht gespeichert" : "Geschwärzt – klicken zum Anzeigen"}
            onClick={(e) => (e.stopPropagation(), setShown(true))}
          >
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}
