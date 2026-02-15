# Solana/Anchor Specialized Agents

## Why Solana Needs Specialized Agents

Generic security scanners often underperform on Solana's unique attack surfaces:
- Account model (not EVM account/balance model)
- Program Derived Addresses (PDAs)
- Cross-Program Invocations (CPI)
- Anchor framework constraints
- Economic attacks specific to DeFi on Solana
- Rent/lamport mechanics

A Solana-specialized swarm would outperform any generic tool on Anchor programs.

## Solana Scanner Agents

### 1. Account Validation Agent
**Focus**: Missing or incorrect account validation checks

**Checks**:
- Missing `has_one` constraints on Anchor accounts
- Missing `#[account(signer)]` on authority accounts
- Missing owner checks (account.owner == expected_program_id)
- Account type confusion (passing a Mint account where TokenAccount expected)
- Missing `#[account(mut)]` where state is modified
- Uninitialized account usage
- Missing close constraints allowing account revival

**Attack Patterns**:
```
- Attacker creates fake account with same data layout
- Passes unauthorized account as authority
- Reuses closed account (revival attack)
- Substitutes account types
```

### 2. CPI (Cross-Program Invocation) Agent
**Focus**: Vulnerabilities in cross-program calls

**Checks**:
- Arbitrary CPI (user-controlled program ID in invoke)
- Missing signer seeds verification in CPI
- Privilege escalation through CPI chains
- Reentrancy via CPI callbacks
- Missing CPI result validation
- Unauthorized CPI with program's PDA signer

**Attack Patterns**:
```
- Attacker passes malicious program ID for CPI target
- Exploits PDA signer authority across program boundaries
- Reentrancy: Program A calls B, B calls back into A
- Privilege escalation through transitive trust
```

### 3. PDA (Program Derived Address) Agent
**Focus**: PDA security issues

**Checks**:
- Seed collision (multiple valid PDAs from different inputs)
- Missing bump seed canonicalization (not using find_program_address)
- PDA spoofing (attacker-controlled seeds)
- Incorrect seed derivation (missing discriminators)
- Seeds that can be manipulated by attacker

**Attack Patterns**:
```
- Craft inputs that produce colliding PDAs
- Use non-canonical bump to create different address
- Control seed components to predict/spoof PDAs
- Missing unique discriminator in seeds
```

### 4. Economic Attack Agent
**Focus**: DeFi-specific economic exploits

**Checks**:
- Oracle manipulation (price feed attacks)
- Flash loan vectors (borrow, manipulate, profit, repay)
- Slippage attacks (sandwich attacks)
- MEV extraction paths
- Liquidity pool manipulation
- Incentive misalignment in tokenomics
- Fee calculation rounding exploitation

**Attack Patterns**:
```
- Manipulate oracle price -> exploit dependent logic -> profit
- Flash loan -> inflate pool -> swap at favorable rate -> deflate
- Front-run large trades with sandwich orders
- Extract value through transaction ordering
```

### 5. State Management Agent
**Focus**: State-related vulnerabilities

**Checks**:
- Stale state reads (reading before update in same tx)
- Initialization attacks (re-initialize already initialized accounts)
- Close account + revival (account closed but reference persists)
- Missing state transition validation (invalid state machine paths)
- Race conditions in multi-instruction transactions
- Account data length manipulation

**Attack Patterns**:
```
- Initialize account twice with different parameters
- Close account -> recreate with malicious data
- Read price before it's updated in same transaction
- Skip required state transitions
```

### 6. Math & Precision Agent
**Focus**: Numerical vulnerabilities

**Checks**:
- Integer overflow/underflow (especially in token math)
- Precision loss in division (truncation exploitation)
- Rounding direction attacks (always rounds in attacker's favor)
- Unsafe casting (u64 -> u32 truncation)
- Multiplication before division (prevent intermediate overflow)
- Zero-amount edge cases

**Attack Patterns**:
```
- Deposit 1 token, get 0 shares (precision loss)
- Overflow check bypass via unchecked math
- Rounding error accumulation over many transactions
- Division by zero panic -> DoS
```

## Solana-Specific Red Team Techniques

The Red Team Agent for Solana programs would:

1. **Build transaction**: Construct a complete Solana transaction targeting the vulnerability
2. **Local validator**: Spin up `solana-test-validator` with program deployed
3. **Execute exploit**: Send the malicious transaction
4. **Verify impact**: Check account states before/after to prove value extraction
5. **Document**: Full transaction bytes + account state diffs

```rust
// Example Red Team PoC structure
#[tokio::test]
async fn exploit_missing_signer_check() {
    // Setup: Deploy program, create accounts
    let mut ctx = TestContext::new().await;

    // Attack: Call privileged instruction without proper signer
    let attacker = Keypair::new();
    let ix = Instruction {
        program_id: ctx.program_id,
        accounts: vec![
            AccountMeta::new(ctx.vault, false),      // vault (should require authority)
            AccountMeta::new(attacker.pubkey(), true), // attacker as "authority"
        ],
        data: withdraw_instruction_data(1_000_000),
    };

    // This should FAIL but succeeds due to missing signer check
    let result = ctx.send_transaction(&[ix], &[&attacker]).await;
    assert!(result.is_ok(), "Exploit succeeded - missing signer check!");

    // Verify: Attacker drained funds
    let vault_balance = ctx.get_balance(ctx.vault).await;
    assert_eq!(vault_balance, 0, "Vault drained by attacker");
}
```

## Solana-Specific Blue Team Considerations

The Blue Team Agent for Solana would check:

1. **Anchor constraints**: Does the Anchor `#[derive(Accounts)]` struct enforce the check?
2. **Runtime guards**: Are there `require!()` or `if` checks in the instruction handler?
3. **Program-level checks**: Does the program validate at a different layer?
4. **Transaction simulation**: Would Solana runtime reject the transaction anyway?
5. **Economic feasibility**: Is the attack profitable after transaction fees?

## Integration with Solana Projects

The swarm is specifically tuned for Solana/Anchor programs including:

- Program instructions (task creation, claiming, completion, disputes)
- Escrow account security
- Agent registration/deregistration flows
- Speculative execution system (bonds, commitments, locks)
- PDA derivation for all protocol accounts
- Economic incentive analysis for task marketplace
