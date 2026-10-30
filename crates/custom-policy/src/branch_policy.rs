use allowit::prelude::*;
/// My agent may pay or deposit only to destinations I approve. A deposit into a vault must also
/// keep total spending within its cap.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only to destinations I approve"
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    // "A deposit into a vault"
    if ctx.request.operation == AllowitOperation::sep56_deposit {
        // "must also keep total spending within its cap"
        allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    }
    Ok(())
}
