// Generated from the exact authored source by allowit-sdk.
use allowit_wallet_protocol::PolicyContext;
pub const SOURCE_PROFILE: &str = "allowit-stellar-transfer-v1";
pub const SOURCE_PROFILE_VERSION: u32 = 1;
pub const ADMITTED_OPERATION: &str = "stellar::sep41_transfer";
pub const SOURCE_HASH: [u8; 32] = [183, 193, 183, 83, 187, 236, 182, 101, 195, 254, 116, 228, 192, 69, 93, 3, 1, 95, 198, 84, 5, 9, 28, 216, 99, 157, 170, 167, 142, 54, 114, 67];
pub const ARGUMENT_SCHEMA_HASH: [u8; 32] = [216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150, 126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139];
pub fn execute(ctx: &PolicyContext) -> bool {
    if ctx.amount <= 0 || ctx.spent_daily < 0 || ctx.spent_total < ctx.spent_daily { return false; }
    let result = (|| -> Result<(), ()> {
        let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "USDC") && ctx.decimals == 7 && ctx.now / 86400 >= ctx.spent_day && (if ctx.now / 86400 == ctx.spent_day { ctx.spent_daily } else { 0i128 }).checked_add(ctx.amount).is_some_and(|next| next <= 50000000i128) { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
        _execute(ctx)
    })();
    result.is_ok()
}
#[allow(unreachable_code, unused_variables)]
fn _execute(ctx: &PolicyContext) -> Result<(), ()> {
    let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "USDC") && ctx.decimals == 7 && ctx.amount <= 20000000i128 { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
    let _ = { if ctx.token == soroban_sdk::String::from_str(ctx.token.env(), "USDC") && ctx.decimals == 7 && ctx.now / 86400 >= ctx.spent_day && (if ctx.now / 86400 == ctx.spent_day { ctx.spent_daily } else { 0i128 }).checked_add(ctx.amount).is_some_and(|next| next <= 50000000i128) { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
    let _ = { if ctx.recipient == soroban_sdk::Address::from_str(ctx.recipient.env(), "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF") { Ok::<(), ()>(()) } else { Err::<(), ()>(()) } }?;
    return { Ok::<(), ()>(()) };
    Err(())
}
