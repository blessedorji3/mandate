import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { AgentChat } from "@/app/agent-chat";

export default async function AgentPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  return (
    <main className="agent-page-shell">
      <AgentChat />
    </main>
  );
}
