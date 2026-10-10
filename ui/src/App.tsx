import { useCallback, useEffect, useState } from "react";
import { api, BINARY_CHANGED, NavItem, onUnauthenticated, VersionInfo } from "./api";
import { navigate, usePath } from "./router";
import { Spinner } from "./components/ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Sites from "./pages/Sites";
import AccessLists from "./pages/AccessLists";
import Certificates from "./pages/Certificates";
import Build from "./pages/Build";
import Caddyfile from "./pages/Caddyfile";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";
import PluginPage from "./pages/PluginPage";
import Analytics from "./pages/Analytics";
import Audit from "./pages/Audit";
import Import from "./pages/Import";
import Mcp from "./pages/Mcp";

const NAV = [
  { path: "/", label: "Dashboard", icon: "◧" },
  { path: "/analytics", label: "Analytics", icon: "📈" },
  { path: "/sites", label: "Sites", icon: "⇄" },
  { path: "/import", label: "Import", icon: "⇪" },
  { path: "/access-lists", label: "Access Lists", icon: "⛨" },
  { path: "/certificates", label: "Zertifikate", icon: "🔒" },
  { path: "/build", label: "Plugins & Build", icon: "⚙" },
  { path: "/caddyfile", label: "Caddyfile", icon: "≣" },
  { path: "/logs", label: "Logs", icon: "☰" },
  { path: "/audit", label: "Audit Log", icon: "📜" },
  { path: "/mcp", label: "KI / MCP", icon: "✦" },
  { path: "/settings", label: "Einstellungen", icon: "⚿" },
];

const PLUGIN_ICONS: Record<string, string> = { shield: "🛡", bot: "🤖", gauge: "⏱", key: "🔑", globe: "🌍" };

/** Sidebar pages of plugins compiled into the running binary. */
function usePluginNav(enabled: boolean): NavItem[] {
  const [items, setItems] = useState<NavItem[]>([]);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const load = async () => {
      try {
        const r = await api.get<{ plugins: NavItem[] | null }>("/api/nav");
        if (alive) setItems(r.plugins ?? []);
      } catch {
        /* keep the last known list */
      }
    };
    load();
    const t = setInterval(load, 60000);
    // A fresh binary needs a moment until the server sees its modules.
    const onChange = () => {
      load();
      setTimeout(load, 3000);
    };
    window.addEventListener(BINARY_CHANGED, onChange);
    return () => {
      alive = false;
      clearInterval(t);
      window.removeEventListener(BINARY_CHANGED, onChange);
    };
  }, [enabled]);
  return items;
}

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
  const pluginNav = usePluginNav(authed === true);

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
  const pluginPage = path.startsWith("/plugin/") ? decodeURIComponent(path.slice("/plugin/".length)) : null;
  let page;
  switch (pluginPage !== null ? "/plugin" : current?.path) {
    case "/plugin":
      page = <PluginPage page={pluginPage!} nav={pluginNav} />;
      break;
    case "/access-lists":
      page = <AccessLists />;
      break;
    case "/certificates":
      page = <Certificates />;
      break;
    case "/":
      page = <Dashboard />;
      break;
    case "/sites":
      page = <Sites />;
      break;
    case "/import":
      page = <Import />;
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
    case "/analytics":
      page = <Analytics />;
      break;
    case "/audit":
      page = <Audit />;
      break;
    case "/mcp":
      page = <Mcp />;
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
        {pluginNav.length > 0 && (
          <>
            <div className="nav-section">Plugins</div>
            {pluginNav.map((n) => {
              const href = "/plugin/" + encodeURIComponent(n.page);
              return (
                <a
                  key={n.page}
                  href={href}
                  title={n.plugin}
                  className={`nav-item ${pluginPage === n.page ? "active" : ""}`}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(href);
                  }}
                >
                  <span aria-hidden="true" style={{ width: 16, textAlign: "center" }}>
                    {PLUGIN_ICONS[n.icon ?? ""] ?? "◇"}
                  </span>
                  {n.label}
                </a>
              );
            })}
          </>
        )}
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
