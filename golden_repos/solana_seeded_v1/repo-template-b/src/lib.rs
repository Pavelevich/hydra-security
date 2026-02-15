use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod template_b {
    use super::*;

    pub fn safe_noop(_ctx: Context<SafeNoop>, amount: u64) -> Result<()> {
        if amount > 0 {
            msg!("amount={}", amount);
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SafeNoop {}
