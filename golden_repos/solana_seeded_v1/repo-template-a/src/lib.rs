use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod template_a {
    use super::*;

    pub fn insecure_withdraw(ctx: Context<InsecureWithdraw>, amount: u64) -> Result<()> {
        // HYDRA_VULN:missing_signer_check
        let _ = amount;
        let _auth = &ctx.accounts.authority;
        Ok(())
    }

    // HYDRA_VULN:arbitrary_cpi
    pub fn insecure_cpi(ctx: Context<InsecureCpi>, target_program: Pubkey) -> Result<()> {
        let _ = (ctx, target_program);
        Ok(())
    }

    pub fn insecure_pda(ctx: Context<InsecurePda>, bump: u8) -> Result<()> {
        let _ = ctx;
        // HYDRA_VULN:non_canonical_bump
        let _ = bump;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InsecureWithdraw<'info> {
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InsecureCpi {}

#[derive(Accounts)]
pub struct InsecurePda {}
