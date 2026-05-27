import { redirect } from "next/navigation";
import { getCurrentSession } from "@/lib/auth";
import { LoginClient } from "@/components/login/LoginClient";

export default async function LoginPage() {
  const session = await getCurrentSession().catch(() => null);
  if (session) {
    redirect("/");
  }

  return <LoginClient />;
}
