"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut, ShieldCheck } from "lucide-react";
import { apiFetch, logout } from "@/lib/api";

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/scans/new", label: "New Scan" },
  { href: "/reports", label: "Reports" },
  { href: "/model", label: "Model" },
  { href: "/settings", label: "Settings" },
];

function navClass(pathname: string, href: string) {
  const active = pathname === href || pathname.startsWith(`${href}/`);
  return [
    "relative inline-flex h-8 items-center rounded-md px-3 text-sm transition-colors",
    active
      ? "text-[var(--brand-300)] after:absolute after:bottom-[-9px] after:left-3 after:right-3 after:h-px after:bg-[var(--brand-500)]"
      : "text-[var(--text-secondary)] hover:bg-[var(--surface-panel)] hover:text-[var(--text-primary)]",
  ].join(" ");
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isLogin = pathname === "/login";
  const [authState, setAuthState] = useState<"checking" | "authenticated" | "unauthenticated">(
    isLogin ? "authenticated" : "checking",
  );
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    if (isLogin) {
      return;
    }

    let active = true;
    apiFetch<{ username: string }>("/api/v1/auth/me")
      .then(() => {
        if (active) {
          setAuthState("authenticated");
        }
      })
      .catch(() => {
        if (active) {
          setAuthState("unauthenticated");
          router.replace("/login");
        }
      });

    return () => {
      active = false;
    };
  }, [isLogin, router]);

  async function handleLogout() {
    setLoggingOut(true);
    setLogoutError(null);
    try {
      await logout();
      setAuthState("unauthenticated");
      router.replace("/login");
      router.refresh();
    } catch (caught) {
      setLogoutError(caught instanceof Error ? caught.message : "Logout failed.");
    } finally {
      setLoggingOut(false);
    }
  }

  const showNav = !isLogin && authState === "authenticated";
  const checking = !isLogin && authState !== "authenticated";

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-[var(--border-subtle)] bg-[var(--surface-canvas)]">
        <div className="mx-auto flex h-12 max-w-[1360px] items-center justify-between gap-8 px-4 md:px-8">
          <Link
            href={showNav ? "/dashboard" : "/login"}
            className="flex shrink-0 items-center gap-2 font-medium text-[var(--text-primary)]"
          >
            <ShieldCheck className="size-5 text-[var(--brand-300)]" />
            URL Threat Checker
          </Link>
          {showNav ? (
            <div className="flex min-w-0 flex-1 items-center justify-end gap-3 text-sm">
              <nav className="flex min-w-0 flex-1 items-center justify-center gap-1">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={navClass(pathname, item.href)}
                  >
                    {item.label}
                  </Link>
                ))}
              </nav>
              <span className="hidden text-[var(--text-secondary)] md:inline">admin</span>
              <span className="hidden h-4 w-px bg-[var(--border-subtle)] md:block" />
              <button
                className="focus-ring ui-button-secondary h-8 px-3 disabled:cursor-not-allowed disabled:opacity-60"
                type="button"
                onClick={handleLogout}
                disabled={loggingOut}
              >
                <LogOut className="size-4" />
                {loggingOut ? "Signing out" : "Sign out"}
              </button>
            </div>
          ) : null}
        </div>
      </header>
      <main className="mx-auto max-w-[1360px] px-4 py-7 md:px-8">
        {logoutError ? (
          <p className="ui-error mb-4 rounded-md px-3 py-2 text-sm">
            {logoutError}
          </p>
        ) : null}
        {checking ? <p className="text-sm ui-muted">Checking session...</p> : children}
      </main>
    </div>
  );
}
