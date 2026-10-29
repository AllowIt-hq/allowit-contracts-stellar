// Generated from the exact authored source by allowit-sdk.
// Placement manifest: {"options":{"default_placement":"auto","expected_transactions":null,"cost_context":null,"cost_estimates":[]},"checks":[{"rule_id":"daily_cap","authority":"owner_pure","requested":"local","selected":"local","reason":"Explicit eligible owner-rule placement"},{"rule_id":"total_cap","authority":"owner_pure","requested":"local","selected":"local","reason":"Explicit eligible owner-rule placement"},{"rule_id":"call_cap","authority":"owner_pure","requested":"local","selected":"local","reason":"Explicit eligible owner-rule placement"}],"possible_shared_spent_writer":false}
#[allow(unused_imports)]
use allowit_wallet_protocol::{PolicyContext,Grant,Spent,EngineState,PolicyEngine,PolicyValue};
pub const SOURCE_PROFILE: &str = "allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION:u32=1;
pub const ADMITTED_OPERATION:&str="stellar::sep41_transfer";
pub const SOURCE_HASH:[u8;32]=[20, 245, 145, 40, 155, 74, 158, 118, 145, 154, 221, 3, 176, 73, 215, 13, 67, 53, 38, 102, 250, 120, 182, 148, 29, 6, 108, 96, 255, 160, 119, 51];
pub const ARGUMENT_SCHEMA_HASH:[u8;32]=[216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()> { if ctx.amount<=0 {return Err(());} _execute(ctx,grant,state,host) }
#[allow(unreachable_code,unused_variables)]
fn _execute(ctx:&PolicyContext,grant:&Grant,state:&EngineState,host:&impl PolicyEngine)->Result<Spent,()> {
    let daily={ {let current={ Ok::<EngineState,()>(state.clone()) }?;let result=allowit_policy_rules::daily_cap(ctx.asset.env().clone(),host.request(),current).map_err(|_|())?;if result.approval{Ok::<Spent,()>(result.spent)}else{Err::<Spent,()>(())}} }?;
    let after_daily={ {let old={ Ok::<EngineState,()>(state.clone()) }?;let next={ Ok::<Spent,()>(daily.clone()) }?;Ok::<EngineState,()>(EngineState{grant:old.grant,spent:next})} }?;
    let total={ {let current={ Ok::<EngineState,()>(after_daily.clone()) }?;let result=allowit_policy_rules::total_cap(ctx.asset.env().clone(),host.request(),current).map_err(|_|())?;if result.approval{Ok::<Spent,()>(result.spent)}else{Err::<Spent,()>(())}} }?;
    let after_total={ {let old={ Ok::<EngineState,()>(after_daily.clone()) }?;let next={ Ok::<Spent,()>(total.clone()) }?;Ok::<EngineState,()>(EngineState{grant:old.grant,spent:next})} }?;
    let calls={ {let current={ Ok::<EngineState,()>(after_total.clone()) }?;let result=allowit_policy_rules::call_cap(ctx.asset.env().clone(),host.request(),current).map_err(|_|())?;if result.approval{Ok::<Spent,()>(result.spent)}else{Err::<Spent,()>(())}} }?;
    let n={ {let map={ Ok::<Spent,()>(calls.clone()) }?;let default={ Ok::<u64,()>(0u64) }?;match map.get(soroban_sdk::String::from_str(ctx.asset.env(),"custom_count")){Some(value)=>match PolicyValue::from_raw(ctx.asset.env(),&value)?{PolicyValue::U64(value)=>Ok::<u64,()>(value),_=>Err::<u64,()>(())},None=>Ok::<u64,()>(default)}} }?;
    let final_spent={ {let mut map={ Ok::<Spent,()>(calls.clone()) }?;let value={ {let a={ Ok::<u64,()>(n) }?;let b={ Ok::<u64,()>(1u64) }?;a.checked_add(b).ok_or(())} }?;map.set(soroban_sdk::String::from_str(ctx.asset.env(),"custom_count"),PolicyValue::U64(value).into_raw(ctx.asset.env()));Ok::<Spent,()>(map)} }?;
    return { Ok::<Spent,()>(final_spent.clone()) };
    Err(())
}
