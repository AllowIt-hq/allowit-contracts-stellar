use allowit::v1::prelude::*;
async fn _execute(ctx: &Context) -> PolicyResult {
    let fits = allowit::amount_at_most(ctx, "2")?;
    if !fits || true { return Ok(()); }
    allowit::fail("unexpected")
}
