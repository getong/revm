use crate::DBErrorMarker;
use auto_impl::auto_impl;
use core::error::Error;
use primitives::{Address, HashMap, B256, U256};
use state::{Account, AccountInfo, Bytecode};

/// Main Revm database interface.
///
/// Contains all the methods that are needed to fetch runtime data from the state.
#[auto_impl(&mut, Box)]
pub trait Database {
    /// The database error type.
    type Error: DBErrorMarker + Error;

    /// Gets basic account information.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error>;

    /// Gets account code by its hash.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error>;

    /// Gets storage value of address at index.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error>;

    /// Gets block hash by block number.
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error>;
}

/// EVM database commit interface.
#[auto_impl(&mut, Box)]
pub trait DatabaseCommit {
    /// Commit changes to the database.
    fn commit(&mut self, changes: HashMap<Address, Account>);
}
