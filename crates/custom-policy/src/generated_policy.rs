// Generated standard preflight only. Full policy code executes offchain.
#[allow(unused_imports)]
use allowit_wallet_protocol::{PolicyContext,Grant,Spent,EngineState,PolicyEngine};
pub const SOURCE_PROFILE:&str="allowit-stellar-std-prefix-v1";
pub const SOURCE_PROFILE_VERSION:u32=1;
pub const ADMITTED_OPERATION:&str="stellar::sep41_transfer";
pub const SOURCE_HASH:[u8;32]=[129, 109, 78, 197, 40, 90, 183, 136, 194, 145, 51, 22, 214, 233, 234, 23, 98, 187, 203, 147, 164, 10, 100, 22, 255, 252, 175, 182, 23, 142, 150, 204];
pub const ARGUMENT_SCHEMA_HASH:[u8;32]=[216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()>{_execute(ctx,grant,state,host)}
#[allow(unused_variables,unused_mut)]
fn _execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()>{
    if ctx.amount<=0{return Err(());}
    let mut working=state.spent.clone();
    let result=allowit_policy_rules::spent_cap(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working.clone()}).map_err(|_|())?;
    if !result.approval{return Err(());}
    working=result.spent;
    let result=allowit_policy_rules::day_spent_cap(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working.clone()}).map_err(|_|())?;
    if !result.approval{return Err(());}
    working=result.spent;
    let result=allowit_policy_rules::day_total_cap(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working.clone()}).map_err(|_|())?;
    if !result.approval{return Err(());}
    working=result.spent;
    let result=allowit_policy_rules::call_cap(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working.clone()}).map_err(|_|())?;
    if !result.approval{return Err(());}
    working=result.spent;
    Ok(working)
}
