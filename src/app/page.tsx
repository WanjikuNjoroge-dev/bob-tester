import { redirect } from "next/navigation";
import { getCurrentSession } from "@/lib/auth";

export default async function SuccessPage() {
  const session = await getCurrentSession().catch(() => null);
  if (!session) {
    redirect("/login");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-black text-center text-[var(--accent)]">
      <p className="font-mono text-xl uppercase tracking-[0.28em]">
        User successfully hacked
      </p>
    </main>
  );
}
