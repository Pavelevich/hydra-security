use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod template_e {
    use super::*;

    pub fn safe_noop(_ctx: Context<SafeNoop>, value: u64) -> Result<()> {
        if value > 0 {
            msg!("value={}", value);
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SafeNoop {}
