use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod template_c {
    use super::*;

    pub fn update_config(ctx: Context<UpdateConfig>) -> Result<()> {
        let _admin = &ctx.accounts.admin;
        // HYDRA_VULN:missing_has_one
        Ok(())
    }

    pub fn relay_cpi(ctx: Context<RelayCpi>, seeds: Vec<u8>) -> Result<()> {
        let _ = (ctx, seeds);
        // HYDRA_VULN:cpi_signer_seed_bypass
        Ok(())
    }

    pub fn derive_bucket(ctx: Context<DeriveBucket>, user_seed: Vec<u8>) -> Result<()> {
        let _ = (ctx, user_seed);
        // HYDRA_VULN:seed_collision
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct RelayCpi {}

#[derive(Accounts)]
pub struct DeriveBucket {}
