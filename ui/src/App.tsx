import { useCallback, useEffect, useState } from "react";
import { api, onUnauthenticated, VersionInfo } from "./api";
import { navigate, usePath } from "./router";
import { Spinner } from "./components/ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Sites from "./pages/Sites";
import Build from "./pages/Build";
import Caddyfile from "./pages/Caddyfile";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";

const NAV = [
  { path: "/", label: "Dashboard", icon: "◧" },
  { path: "/sites", label: "Sites", icon: "⇄" },
  { path: "/build", label: "Plugins & Build", icon: "⚙" },
  { path: "/caddyfile", label: "Caddyfile", icon: "≣" },
  { path: "/logs", label: "Logs", icon: "☰" },
  { path: "/settings", label: "Einstellungen", icon: "⚿" },
];

type Theme = "system" | "light" | "dark";

function loadTheme(): Theme {
  try {
    const v = localStorage.getItem("cf-theme");
    if (v === "light" || v === "dark") return v;
  } catch {
    /* storage unavailable */
  }
  return "system";
}

export default function App() {
  const path = usePath();
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [theme, setTheme] = useState<Theme>(loadTheme);

  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("cf-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const probe = useCallback(async () => {
    try {
      setVersion(await api.get<VersionInfo>("/api/version"));
    } catch {
      /* shown on login page */
    }
    try {
      await api.get("/api/session");
      setAuthed(true);
    } catch {
      setAuthed(false);
    }
  }, []);

  useEffect(() => {
    probe();
    return onUnauthenticated(() => setAuthed(false));
  }, [probe]);

  if (authed === null) {
    return (
      <div className="login-wrap">
        <Spinner />
      </div>
    );
  }
  if (!authed) {
    return <Login version={version} onLogin={() => setAuthed(true)} />;
  }

  const current = NAV.find((n) => n.path === path) ?? (path === "/" ? NAV[0] : null);
  let page;
  switch (current?.path) {
    case "/":
      page = <Dashboard />;
      break;
    case "/sites":
      page = <Sites />;
      break;
    case "/build":
      page = <Build />;
      break;
    case "/caddyfile":
      page = <Caddyfile />;
      break;
    case "/logs":
      page = <Logs />;
      break;
    case "/settings":
      page = <Settings onLogout={() => setAuthed(false)} />;
      break;
    default:
      page = (
        <div className="empty">
          Seite nicht gefunden.{" "}
          <a href="/" onClick={(e) => (e.preventDefault(), navigate("/"))}>
            Zum Dashboard
          </a>
        </div>
      );
  }

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Hauptnavigation">
        <div className="brand">
          <span className="brand-mark">C</span> caddyforge
        </div>
        {NAV.map((n) => (
          <a
            key={n.path}
            href={n.path}
            className={`nav-item ${current?.path === n.path ? "active" : ""}`}
            onClick={(e) => {
              e.preventDefault();
              navigate(n.path);
            }}
          >
            <span aria-hidden="true" style={{ width: 16, textAlign: "center" }}>
              {n.icon}
            </span>
            {n.label}
          </a>
        ))}
        <div className="sidebar-foot">
          <label className="row small">
            Theme
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)} style={{ width: "auto", padding: "2px 6px" }}>
              <option value="system">System</option>
              <option value="light">Hell</option>
              <option value="dark">Dunkel</option>
            </select>
          </label>
          <span>{version ? `caddyforge ${version.version}` : ""}</span>
        </div>
      </nav>
      <main className="main">{page}</main>
    </div>
  );
}
