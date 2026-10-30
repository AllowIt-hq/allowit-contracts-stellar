use allowit::prelude::*;
pub fn execute(ctx: &AllowitEnv) -> allowit::Result {
    allowit::transaction_cap(ctx, &ctx.grant.transaction_cap)?;
    allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    allowit::day_spent_cap(ctx, &ctx.grant.day_spent_cap)?;
    allowit::day_total_cap(ctx, &ctx.grant.day_total_cap)?;
    allowit::call_cap(ctx, &ctx.grant.call_cap)?;
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    allowit::tokens(ctx, &ctx.grant.tokens)?;
    allowit::expiry(ctx, &ctx.grant.expiry)?;
    Ok(())
}
