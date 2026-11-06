import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

import { createClient } from "@/lib/supabase/server";
import { BlocklistReviewPanel } from "@/app/review-panel";

export default async function ReviewPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  return (
    <main className="agent-page-shell">
      <BlocklistReviewPanel />
    </main>
  );
}
