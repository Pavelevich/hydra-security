use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod holdout_one {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        // HYDRA_VULN:missing_signer_check
        let _ = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn relay(ctx: Context<Relay>) -> Result<()> {
        // HYDRA_VULN:cpi_reentrancy
        let _ = ctx;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Relay {}
