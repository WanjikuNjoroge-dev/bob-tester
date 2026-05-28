"use client";

import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { useState } from "react";

export function LogoutButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  async function handleLogout() {
    setLoading(true);

    try {
      await fetch("/api/auth/logout", { method: "POST" });
      router.push("/login");
      router.refresh();
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleLogout}
      disabled={loading}
      className="inline-flex h-12 items-center justify-center gap-3 border border-[var(--line-strong)] bg-transparent px-5 font-mono text-xs uppercase tracking-[0.24em] text-[var(--accent)] transition hover:bg-[rgba(113,255,173,0.08)] disabled:cursor-not-allowed disabled:opacity-50"
    >
      <LogOut className="h-4 w-4" />
      {loading ? "Exiting" : "Logout"}
    </button>
  );
}
