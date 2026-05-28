import { redirect } from "next/navigation";
import { getCurrentSession } from "@/lib/auth";
import { LogoutButton } from "@/components/auth/LogoutButton";

export default async function SuccessPage() {
  const session = await getCurrentSession().catch(() => null);
  if (!session) {
    redirect("/login");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-black px-6 text-center text-[var(--accent)]">
      <div className="flex flex-col items-center gap-8">
        <p className="font-mono text-xl uppercase tracking-[0.28em]">
          User successfully hacked
        </p>
        <LogoutButton />
      </div>
    </main>
  );
}
