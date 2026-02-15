use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod template_d {
    use super::*;

    pub fn forward(ctx: Context<Forward>, target_program: Pubkey) -> Result<()> {
        let _ = (ctx, target_program);
        // HYDRA_VULN:arbitrary_cpi
        Ok(())
    }

    pub fn parse_account(ctx: Context<ParseAccount>) -> Result<()> {
        let unchecked = &ctx.accounts.state_any;
        let _ = unchecked;
        // HYDRA_VULN:account_type_confusion
        Ok(())
    }

    pub fn derive_profile(ctx: Context<DeriveProfile>, seed: Vec<u8>) -> Result<()> {
        let _ = (ctx, seed);
        // HYDRA_VULN:attacker_controlled_seed
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Forward {}

#[derive(Accounts)]
pub struct ParseAccount<'info> {
    pub state_any: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DeriveProfile {}
