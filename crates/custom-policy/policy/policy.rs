use allowit::prelude::*;
/// Let my agent pay our suppliers from this wallet. Cap every payment, cap its total spending,
/// cap its spending each day and cap the daily volume it moves. Limit how many payments it makes.
/// Pay only suppliers I approve, use only USDC, and stop when the grant expires.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Cap every payment"
    allowit::transaction_cap(ctx, &ctx.grant.transaction_cap)?;
    // "cap its total spending"
    allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    // "cap its spending each day"
    allowit::day_spent_cap(ctx, &ctx.grant.day_spent_cap)?;
    // "cap the daily volume it moves"
    allowit::day_total_cap(ctx, &ctx.grant.day_total_cap)?;
    // "Limit how many payments it makes"
    allowit::call_cap(ctx, &ctx.grant.call_cap)?;
    // "Pay only suppliers I approve"
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    // "use only USDC"
    allowit::tokens(ctx, &ctx.grant.tokens)?;
    // "stop when the grant expires"
    allowit::expiry(ctx, &ctx.grant.expiry)?;
    Ok(())
}
