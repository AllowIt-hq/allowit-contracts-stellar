// Generated from the exact authored source by allowit-sdk.
// Placement manifest: {"options":{"default_placement":"auto","expected_transactions":null,"cost_context":null,"cost_estimates":[]},"checks":[{"rule_id":"asset_label","authority":"owner_pure","requested":"auto","selected":"local","reason":"Missing compatible cost estimates; owner authority default"},{"rule_id":"recipient_is","authority":"owner_pure","requested":"auto","selected":"local","reason":"Missing compatible cost estimates; owner authority default"}],"possible_shared_spent_writer":false}
#[allow(unused_imports)]
use allowit_wallet_protocol::{PolicyContext,Grant,Spent,EngineState,PolicyEngine};
#[allow(unused_imports)]
use soroban_sdk::IntoVal;
pub const SOURCE_PROFILE:&str="allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION:u32=1;
pub const ADMITTED_OPERATION:&str="stellar::sep41_transfer";
pub const SOURCE_HASH:[u8;32]=[236, 255, 20, 81, 203, 170, 24, 194, 201, 124, 188, 114, 178, 139, 151, 162, 145, 89, 172, 253, 221, 175, 11, 169, 43, 70, 58, 212, 46, 64, 82, 53];
pub const ARGUMENT_SCHEMA_HASH:[u8;32]=[216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()> {
    if ctx.amount<=0{return Err(());}
    let mut working_spent=state.spent.clone();
    _execute(ctx,grant,&mut working_spent,host)?;
    Ok(working_spent)
}
#[allow(unused_variables,unreachable_code)]
fn _execute(ctx:&PolicyContext,grant:&Grant,working_spent:&mut Spent,host:&impl PolicyEngine)->Result<(),()>{
    let _ = { {let result=allowit_policy_rules::asset_label(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working_spent.clone()},soroban_sdk::String::from_str(ctx.asset.env(),"XLM")).map_err(|_|())?;if result.approval{*working_spent=result.spent;Ok::<(),()>(())}else{Err::<(),()>(())}} }?;
    let _ = { {let result=allowit_policy_rules::asset_label(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working_spent.clone()},soroban_sdk::String::from_str(ctx.asset.env(),"XLM")).map_err(|_|())?;if result.approval{*working_spent=result.spent;Ok::<(),()>(())}else{Err::<(),()>(())}} }?;
    let _ = { {let result=allowit_policy_rules::recipient_is(ctx.asset.env().clone(),host.request(),EngineState{grant:grant.clone(),spent:working_spent.clone()},soroban_sdk::Address::from_str(ctx.asset.env(),"CBNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVXQOK")).map_err(|_|())?;if result.approval{*working_spent=result.spent;Ok::<(),()>(())}else{Err::<(),()>(())}} }?;
    return { Ok::<(),()>(()) };
    Err(())
}
