use allowit::prelude::*;
/// Let my agent pay our suppliers from this wallet. Cap every payment, cap its total spending,
/// cap its spending each day and cap the daily volume it moves. Limit how many payments it makes.
/// Pay only suppliers I approve, use only USDC, and stop when the params expire. Let it only make
/// payments.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Cap every payment"
    allowit::transaction_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP))?;
    // "cap its total spending"
    allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
    // "cap its spending each day"
    allowit::day_spent_cap(ctx, ctx.params.get(allowit::DAY_SPENT_CAP))?;
    // "cap the daily volume it moves"
    allowit::day_total_cap(ctx, ctx.params.get(allowit::DAY_TOTAL_CAP))?;
    // "Limit how many payments it makes"
    allowit::call_cap(ctx, ctx.params.get(allowit::CALL_CAP))?;
    // "Pay only suppliers I approve"
    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
    // "use only USDC"
    allowit::tokens(ctx, ctx.params.get(allowit::TOKENS))?;
    // "stop when the params expire"
    allowit::expiry(ctx, ctx.params.get(allowit::EXPIRY))?;
    // "only make payments"
    allowit::operations(ctx, ctx.params.get(allowit::OPERATIONS))?;
    Ok(())
}
