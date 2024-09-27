use alloy::sol;

sol! {
    #[sol(rpc)]
    contract L1Block {
        #[derive(Debug, Default)]
        function number() public returns(uint64);

        #[derive(Debug, Default)]
        function hash() public returns(bytes32);
    }

    #[sol(rpc)]
    contract AnchorStateRegistry {
        #[derive(Debug, Default)]
        struct OutputRoot {
            bytes32 root;
            uint256 l2BlockNumber;
        }

        #[derive(Debug, Default)]
        function anchors(uint32) public returns(OutputRoot);
    }
}
