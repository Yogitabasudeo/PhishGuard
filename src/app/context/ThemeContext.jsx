import { createContext, useContext, useState, useLayoutEffect } from "react";

const ThemeContext = createContext(null);
const THEMES = ["light", "dark", "midnight"];
const STORAGE_KEY = "phishguard_theme";

function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    const t = THEMES.includes(stored) ? stored : "midnight";
    // Apply immediately (sync) to prevent flash of wrong theme
    document.documentElement.classList.add(`theme-${t}`);
    return t;
  });

  useLayoutEffect(() => {
    const html = document.documentElement;
    THEMES.forEach((t) => html.classList.remove(`theme-${t}`));
    html.classList.add(`theme-${theme}`);
    localStorage.setItem(STORAGE_KEY, theme);
  }, [theme]);

  const setTheme = (t) => {
    if (THEMES.includes(t)) setThemeState(t);
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme, themes: THEMES }}>
      {children}
    </ThemeContext.Provider>
  );
}

function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

export { ThemeProvider, useTheme };
