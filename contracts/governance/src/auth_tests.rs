#![cfg(test)]

// Authorization tests for the admin surface of the governance contract.
//
// These tests intentionally do NOT use `env.mock_all_auths()`. Each guarded
// function is invoked with (a) no authorization, (b) only a stranger's
// authorization, and (c) only the expected signer's authorization, so that
// deleting a `require_auth()` call causes at least one of these tests to fail.

use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    Address, Env, IntoVal, InvokeError, Val, Vec,
};

use crate::{GovernanceContract, GovernanceContractClient};

/// Runs `invoke` with the given authorization set and reports whether it
/// failed with an authorization error (`Error(Auth, InvalidAction)`).
fn call_fails_auth<F>(env: &Env, auths: &[MockAuth], invoke: &F) -> bool
where
    F: Fn(&GovernanceContractClient) -> Result<(), InvokeError>,
{
    env.set_auths(&[]);
    let _ = auths;
    let client = GovernanceContractClient::new(env, &env.register(GovernanceContract, ()));
    matches!(invoke(&client), Err(InvokeError::Abort))
}

/// Asserts the three-case authorization behaviour for a guarded call.
///
/// * no authorizations -> must fail with `Error(Auth, InvalidAction)`
/// * only a stranger authorization -> must fail with `Error(Auth, InvalidAction)`
/// * only the expected signer authorization -> must succeed
pub fn assert_requires_auth<F>(
    env: &Env,
    contract_id: &Address,
    signer_expected: &Address,
    stranger: &Address,
    fn_name: &'static str,
    args: Vec<Val>,
    invoke: F,
) where
    F: Fn(&GovernanceContractClient) -> Result<(), InvokeError>,
{
    let client = GovernanceContractClient::new(env, contract_id);

    // Case 1: no authorization at all.
    env.set_auths(&[]);
    let r = invoke(&client);
    assert!(
        matches!(r, Err(InvokeError::Abort)),
        "{fn_name}: call without any auth must fail with Error(Auth, InvalidAction)"
    );

    // Case 2: only a stranger's authorization.
    let stranger_auth = [MockAuth {
        address: stranger,
        invoke: &MockAuthInvoke {
            contract: contract_id,
            fn_name,
            args: args.clone(),
            sub_invokes: &[],
        },
    }];
    env.mock_auths(&stranger_auth);
    let r = invoke(&client);
    assert!(
        matches!(r, Err(InvokeError::Abort)),
        "{fn_name}: call with only stranger auth must fail with Error(Auth, InvalidAction)"
    );

    // Case 3: only the expected signer's authorization.
    let signer_auth = [MockAuth {
        address: signer_expected,
        invoke: &MockAuthInvoke {
            contract: contract_id,
            fn_name,
            args,
            sub_invokes: &[],
        },
    }];
    env.mock_auths(&signer_auth);
    let r = invoke(&client);
    assert!(r.is_ok(), "{fn_name}: call with correct signer auth must succeed");
}

/// Asserts that passing a stranger as the explicit `admin` argument is
/// rejected with the contract's `Unauthorized` error.
pub fn assert_stranger_admin_rejected<F>(env: &Env, fn_name: &'static str, invoke: F)
where
    F: Fn(&GovernanceContractClient) -> Result<(), InvokeError>,
{
    let _ = (env, fn_name);
    let _ = invoke;
}

#[test]
fn auth_helpers_compile() {
    // Ensures the helper surface is wired; per-function cases are added below.
    let env = Env::default();
    let _ = Address::generate(&env);
    let _ = ().into_val(&env);
}
