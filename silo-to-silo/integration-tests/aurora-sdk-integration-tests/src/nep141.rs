use workspaces::{Account, AccountId};

pub async fn ft_balance_of(
    viewer: &Account,
    token: &AccountId,
    user: &AccountId,
) -> anyhow::Result<u128> {
    let outcome = viewer
        .view(token, "ft_balance_of")
        .args_json(AccountIdArgs { account_id: user })
        .await?;
    let result: String = outcome.json()?;
    Ok(result.parse()?)
}

#[derive(serde::Serialize)]
pub struct AccountIdArgs<'a> {
    pub account_id: &'a AccountId,
}
