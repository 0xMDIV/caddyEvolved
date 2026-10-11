import { useMemo, useState } from "react";

// ISO 3166-1 alpha-2 codes; names come from the browser (Intl.DisplayNames).
const CODES =
  "AD AE AF AG AI AL AM AO AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CD CF CG CH CI CK CL CM CN CO CR CU CV CW CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IM IN IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SI SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TG TH TJ TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA VC VE VG VI VN VU WS XK YE YT ZA ZM ZW".split(" ");

const names = (() => {
  try {
    return new Intl.DisplayNames(["de"], { type: "region" });
  } catch {
    return null;
  }
})();

export const countryName = (c: string) => {
  try {
    return names?.of(c) ?? c;
  } catch {
    return c;
  }
};

export const COUNTRY_PRESETS: Record<string, string[]> = {
  DACH: ["DE", "AT", "CH"],
  EU: "AT BE BG CY CZ DE DK EE ES FI FR GR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK".split(" "),
};

/** CountryPicker edits a list of country codes with search and chips. */
export function CountryPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [q, setQ] = useState("");
  const options = useMemo(() => CODES.map((c) => ({ c, n: countryName(c) })).sort((a, b) => a.n.localeCompare(b.n, "de")), []);
  const hits = q.trim()
    ? options.filter((o) => !value.includes(o.c) && (o.c.toLowerCase() === q.trim().toLowerCase() || o.n.toLowerCase().includes(q.trim().toLowerCase()))).slice(0, 8)
    : [];
  const add = (c: string) => {
    onChange([...value.filter((x) => x !== c), c].sort());
    setQ("");
  };
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="chips">
        {value.map((c) => (
          <span key={c} className="chip">
            {countryName(c)} <span className="mono muted">{c}</span>
            <button type="button" aria-label={`${c} entfernen`} onClick={() => onChange(value.filter((x) => x !== c))}>
              ×
            </button>
          </span>
        ))}
        {value.length === 0 && <span className="muted small">noch keine Länder</span>}
      </div>
      <input
        value={q}
        placeholder="Land suchen, z. B. Deutschland oder DE"
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && hits[0]) {
            e.preventDefault();
            add(hits[0].c);
          }
        }}
      />
      {hits.length > 0 && (
        <div className="chips">
          {hits.map((h) => (
            <button key={h.c} type="button" className="btn sm" onClick={() => add(h.c)}>
              + {h.n} <span className="mono muted">{h.c}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
