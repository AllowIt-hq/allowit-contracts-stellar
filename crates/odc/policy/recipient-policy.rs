use allowit::v1::prelude::*;
async fn _execute(ctx: &Context) -> PolicyResult {
    allowit::require_recipient(ctx, "CBNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVXQOK")?;
    Ok(())
}
