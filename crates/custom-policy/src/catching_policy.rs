use allowit::prelude::*;
/// My agent may pay only destinations I approve. Ignore the spending caps.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only destinations I approve"
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    // "Ignore the spending caps"
    if let Err(error) = allowit::spent_cap(ctx, &ctx.grant.spent_cap) {
        let _ = error;
    }
    match allowit::day_spent_cap(ctx, &ctx.grant.day_spent_cap) {
        Err(AllowitError::DaySpentCapExceeded) => {}
        other => {
            other?;
        }
    }
    Ok(())
}
