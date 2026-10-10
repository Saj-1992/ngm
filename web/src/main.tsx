import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { setNonce } from "get-nonce";
import { App } from "./App";
import { I18nProvider } from "./i18n/i18n";
import { SessionProvider } from "./lib/session";
import { ThemeProvider } from "./lib/theme";
import { BASE } from "./lib/base";
import "./styles.css";

// The server issues a per-response CSP nonce; libraries that inject <style>
// elements (Radix scroll lock) must carry it to pass style-src.
const nonce = document.querySelector<HTMLMetaElement>("meta[name=ngm-csp-nonce]")?.content;
if (nonce && !nonce.startsWith("__")) setNonce(nonce);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <I18nProvider>
        <TooltipProvider delayDuration={300}>
          <BrowserRouter basename={BASE || undefined}>
            <SessionProvider>
              <App />
            </SessionProvider>
          </BrowserRouter>
        </TooltipProvider>
      </I18nProvider>
    </ThemeProvider>
  </StrictMode>,
);
