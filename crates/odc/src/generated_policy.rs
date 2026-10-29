// Generated from the exact authored source by allowit-sdk.
// Placement manifest: {"options":{"default_placement":"auto","expected_transactions":null,"cost_context":null,"cost_estimates":[]},"checks":[],"possible_shared_spent_writer":false}
#[allow(unused_imports)]
use allowit_wallet_protocol::{PolicyContext,Grant,Spent,EngineState,PolicyEngine};
#[allow(unused_imports)]
use soroban_sdk::IntoVal;
pub const SOURCE_PROFILE:&str="allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION:u32=1;
pub const ADMITTED_OPERATION:&str="stellar::sep41_transfer";
pub const SOURCE_HASH:[u8;32]=[54, 69, 162, 124, 60, 62, 24, 41, 203, 23, 34, 61, 21, 222, 29, 113, 250, 151, 130, 97, 186, 115, 140, 24, 6, 168, 230, 120, 13, 170, 69, 84];
pub const ARGUMENT_SCHEMA_HASH:[u8;32]=[216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()> {
    if ctx.amount<=0{return Err(());}
    let mut working_spent=state.spent.clone();
    _execute(ctx,grant,&mut working_spent,host)?;
    Ok(working_spent)
}
#[allow(unused_variables,unreachable_code)]
fn _execute(ctx:&PolicyContext,grant:&Grant,working_spent:&mut Spent,host:&impl PolicyEngine)->Result<(),()>{
    return { Ok::<(),()>(()) };
    Err(())
}
