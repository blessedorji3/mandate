create policy "Trusted service role manages NEAR transfer challenges"
on mandate_private.near_transfer_challenges
for all to service_role
using (true) with check (true);

create policy "Trusted service role manages NEAR transfer receipts"
on mandate_private.near_transfer_receipts
for all to service_role
using (true) with check (true);
