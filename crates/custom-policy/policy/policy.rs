use allowit::prelude::*;
async fn _execute(ctx: &Context) -> PolicyResult {
    allowit::spent_cap(grant::spent_cap)?;
    allowit::day_spent_cap(grant::day_spent_cap)?;
    allowit::day_total_cap(grant::day_total_cap)?;
    allowit::call_cap(grant::call_cap)?;
    Ok(())
}
