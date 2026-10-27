use allowit::v1::prelude::*;
async fn _execute(ctx: &Context) -> PolicyResult {
 allowit::cap_per_transaction(ctx, "2", "USDC")?;
 allowit::set_cap_per_day(ctx, "5", "USDC")?;
 allowit::require_recipient(ctx, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")?;
 Ok(())
}
