//! Native policy source, copied byte-for-byte into both chain builds.
//! Amounts use crate::policy_api::*;

pub fn execute(ctx: &Context) -> Result<u64, PolicyError> {
    require_approval(ctx)?;
    enforce_daily_limit(ctx)
}
