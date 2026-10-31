use allowit::prelude::*;
/// My agent may pay only destinations I approve. It may exceed its daily spending cap twice; count
/// each time. A payment that names an invoice must stay within my invoice cap.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only destinations I approve"
    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
    match allowit::day_spent_cap(ctx, ctx.params.get(allowit::DAY_SPENT_CAP)) {
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
    // "A payment that names an invoice"
    if ctx.request.args.get("invoice").is_some() {
        // "must stay within my invoice cap"
        allowit::transaction_cap(ctx, ctx.params.get("invoice_cap"))?;
    }
    Ok(())
}
