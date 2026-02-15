use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod control_f {
    use super::*;

    pub fn initialize(_ctx: Context<Initialize>, amount: u64) -> Result<()> {
        if amount > 0 {
            msg!("init amount={}", amount);
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
