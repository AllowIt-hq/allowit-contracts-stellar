// Generated from the exact authored source by allowit-sdk.
use allowit_wallet_protocol::PolicyContext;
pub const SOURCE_PROFILE: &str = "allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION: u32 = 1;
pub const ADMITTED_OPERATION: &str = "stellar::sep41_transfer";
pub const SOURCE_HASH: [u8; 32] = [236, 255, 20, 81, 203, 170, 24, 194, 201, 124, 188, 114, 178, 139, 151, 162, 145, 89, 172, 253, 221, 175, 11, 169, 43, 70, 58, 212, 46, 64, 82, 53];
pub const ARGUMENT_SCHEMA_HASH: [u8; 32] = [216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx: &PolicyContext) -> bool {
    if ctx.amount <= 0 || ctx.spent_daily < 0 || ctx.spent_total < ctx.spent_daily { return false; }
    let result = (|| -> Result<(), ()> {
        let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "XLM") && ctx.decimals == 7 { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
        _execute(ctx)
    })();
    result.is_ok()
}
#[allow(unreachable_code, unused_variables)]
fn _execute(ctx: &PolicyContext) -> Result<(), ()> {
    let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "XLM") && ctx.decimals == 7 { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
    let _ = { if ctx.recipient == soroban_sdk::Address::from_str(ctx.recipient.env(), "CBNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVXQOK") { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
    return { Ok::<(), ()>(()) };
    Err(())
}
