import { useEffect, useState } from "react";

// Minimal history router: the Go SPA handler serves index.html for any
// extension-less path, so real URLs survive a reload.
const listeners = new Set<() => void>();

export function navigate(path: string) {
  if (path === window.location.pathname) return;
  window.history.pushState(null, "", path);
  listeners.forEach((fn) => fn());
}

export function usePath(): string {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const update = () => setPath(window.location.pathname);
    listeners.add(update);
    window.addEventListener("popstate", update);
    return () => {
      listeners.delete(update);
      window.removeEventListener("popstate", update);
    };
  }, []);
  return path;
}
