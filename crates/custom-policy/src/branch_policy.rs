use allowit::prelude::*;
/// Test policy: deposits also need the lifetime cap. It branches on a typed request field.
pub fn execute(ctx: &AllowitEnv) -> allowit::Result {
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    if ctx.request.operation == Operation::sep56_deposit {
        allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    }
    Ok(())
}
