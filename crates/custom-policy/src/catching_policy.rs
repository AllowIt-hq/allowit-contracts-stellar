use allowit::prelude::*;
/// My agent may pay only destinations I approve. It may exceed its daily spending cap twice; count
/// each time.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only destinations I approve"
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    match allowit::day_spent_cap(ctx, &ctx.grant.day_spent_cap) {
        // "It may exceed its daily spending cap twice"
        Err(AllowitError::DaySpentCapExceeded) => {
            // "count each time"
            let over: u64 = allowit::get_state(ctx, "over_day_cap")?.unwrap_or(0);
            if over >= 2 {
                return Err(AllowitError::DaySpentCapExceeded);
            }
            allowit::set_state(ctx, "over_day_cap", over + 1)?;
        }
        other => {
            other?;
        }
    }
    Ok(())
}
