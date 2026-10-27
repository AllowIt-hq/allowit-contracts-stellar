// Generated from the exact authored source by allowit-sdk.
use allowit_wallet_protocol::PolicyContext;
pub const SOURCE_PROFILE: &str = "allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION: u32 = 1;
pub const ADMITTED_OPERATION: &str = "stellar::sep41_transfer";
pub const SOURCE_HASH: [u8; 32] = [76, 242, 183, 184, 146, 147, 52, 183, 70, 231, 175, 2, 33, 52, 60, 125, 78, 89, 93, 182, 204, 228, 149, 122, 193, 130, 120, 15, 5, 12, 200, 129];
pub const ARGUMENT_SCHEMA_HASH: [u8; 32] = [216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx: &PolicyContext) -> bool {
    if ctx.amount <= 0 || ctx.spent_daily < 0 || ctx.spent_total < ctx.spent_daily { return false; }
    let result = (|| -> Result<(), ()> {
        _execute(ctx)
    })();
    result.is_ok()
}
#[allow(unreachable_code, unused_variables)]
fn _execute(ctx: &PolicyContext) -> Result<(), ()> {
    let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "USDC") && ctx.decimals == 7 { Ok::<bool, ()>(ctx.amount <= 20000000i128) } else { Err::<bool, ()>(()) } }?;
    if { Ok::<bool, ()>(({ Ok::<bool, ()>(!({ if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "USDC") && ctx.decimals == 7 { Ok::<bool, ()>(ctx.amount <= 20000000i128) } else { Err::<bool, ()>(()) } }?)) }?) || ({ Ok::<bool, ()>(true) }?)) }? {
        return { Ok::<(), ()>(()) };
    } else {
    }
    return { Err::<(), ()>(()) };
    Err(())
}
