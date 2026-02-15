use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod holdout_two {
    use super::*;

    pub fn derive(ctx: Context<Derive>, bump: u8) -> Result<()> {
        // HYDRA_VULN:non_canonical_bump
        let _ = (ctx, bump);
        Ok(())
    }

    pub fn update(ctx: Context<Update>) -> Result<()> {
        // HYDRA_VULN:missing_has_one
        let _ = ctx;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Derive {}

#[derive(Accounts)]
pub struct Update<'info> {
    pub admin: AccountInfo<'info>,
}
