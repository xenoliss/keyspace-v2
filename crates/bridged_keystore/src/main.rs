use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::{
    hex::ToHexExt,
    providers::{Provider, ProviderBuilder},
};
use std::str::FromStr;

use crate::bindings::{AnchorStateRegistry, L1Block};

mod bindings;

#[tokio::main]

async fn main() {
    let base_sepolia_rpc_url = "https://sepolia.base.org".parse().unwrap();
    let base_sepolia_provider = ProviderBuilder::new().on_http(base_sepolia_rpc_url);

    let eth_sepolia_rpc_url = "https://sepolia.gateway.tenderly.co".parse().unwrap();
    let eth_sepolia_provider = ProviderBuilder::new().on_http(eth_sepolia_rpc_url);

    let l1_block_contract = L1Block::new(
        Address::from_str("0x4200000000000000000000000000000000000015").unwrap(),
        &base_sepolia_provider,
    );

    let anchor_state_registry_contract = AnchorStateRegistry::new(
        Address::from_str("0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205").unwrap(),
        &eth_sepolia_provider,
    );

    // Read the latest OutputRoot from the AnchorStateRegistry L1 contract.
    let output_root = anchor_state_registry_contract
        .anchors(0)
        .call()
        .await
        .unwrap()
        ._0;
    println!("AnchorStateRegistry OutputRoot: {output_root:?}");

    // Get the l2 state at the block that has been commited to the AnchorStateRegistry L1 contract.
    let commited_l2_block_number = output_root.l2BlockNumber.as_limbs()[0];
    let l2_block = base_sepolia_provider
        .get_block_by_number(BlockNumberOrTag::Number(commited_l2_block_number), true)
        .await
        .unwrap()
        .unwrap();

    let l2_block_hash = l2_block.header.hash;
    let l2_state_root = l2_block.header.state_root;
    let message_passer_storage_hash = base_sepolia_provider
        .get_proof(
            Address::from_str("0x4200000000000000000000000000000000000016").unwrap(),
            vec![],
        )
        .block_id(commited_l2_block_number.into())
        .await
        .unwrap()
        .storage_hash;
    println!("settled l2 state root {l2_state_root:?}");
    println!("settled l2 to l1 message passer storage hash {message_passer_storage_hash:?}");
    println!("settled l2 block hash {l2_block_hash:?}");

    // Read the current L2 block number and fetch the correspondib L1 block number available from
    // the L1Block oracle contract.
    let current_l2_block_number = base_sepolia_provider.get_block_number().await.unwrap();
    println!("current l2 block number {current_l2_block_number:?}");

    let l1_block_number = l1_block_contract
        .number()
        .block(current_l2_block_number.into())
        .call()
        .await
        .unwrap()
        ._0;

    println!("l1 block number: {l1_block_number}");

    // Get the corresponding L1 block and print the RLP header.
    let l1_block = eth_sepolia_provider
        .get_block_by_number(BlockNumberOrTag::Number(l1_block_number), true)
        .await
        .unwrap()
        .unwrap();

    let header: alloy_consensus::Header = l1_block.header.try_into().unwrap();
    println!("{}", alloy_rlp::encode(&header).encode_hex());
}
