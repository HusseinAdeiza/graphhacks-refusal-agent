"""Contracts, functions, protocols, and relationships.

CONTRACTS: name, address (None when not publicly pinned), chain, kind, protocol.
FUNCTIONS: per contract, with optional CALLS targets ("Contract.function") and
vulnerabilities: list of (swc, source, status) where status is one of
exploited | patched | pattern | theoretical.

Protocol list is derived from the protocols field.
"""

CONTRACTS = [
    # --- audited live protocols (15) ---
    dict(name="TheDAO", address="0xbb9bc244d798123fde783fcc1c72d3bb8c189413", chain="Ethereum", kind="legacy", protocol="DAO"),
    dict(name="UniswapV2Router02", address="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", chain="Ethereum", kind="dex", protocol="Uniswap"),
    dict(name="UniswapV3Router2", address="0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", chain="Ethereum", kind="dex", protocol="Uniswap"),
    dict(name="AaveV3Pool", address="0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", chain="Ethereum", kind="lending", protocol="Aave"),
    dict(name="AaveV2LendingPool", address="0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9", chain="Ethereum", kind="lending", protocol="Aave"),
    dict(name="CompoundComptroller", address="0x3d9819210A31b48718aC728fB26cBbB3CCdd9197", chain="Ethereum", kind="lending", protocol="Compound"),
    dict(name="cUSDC", address="0x39aa39c021dfbae8fac545936693ac917d5e7563", chain="Ethereum", kind="lending", protocol="Compound"),
    dict(name="Curve3pool", address="0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7", chain="Ethereum", kind="dex", protocol="Curve"),
    dict(name="BalancerVault", address="0xba100000625a570e4145b50d0339185608d6a16f", chain="Ethereum", kind="dex", protocol="Balancer"),
    dict(name="MakerVault", address="0x0d500B1d8E8eF31E21C99d1Db9A7c3793F7Fe872", chain="Ethereum", kind="cdp", protocol="MakerDAO"),
    dict(name="SushiswapRouter02", address="0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", chain="Ethereum", kind="dex", protocol="Sushiswap"),
    dict(name="1inchv3", address="0x1111111254EEB25477B68fb85Ed929f73A960582", chain="Ethereum", kind="aggregator", protocol="1inch"),
    dict(name="OpenSeaSeaport", address="0x000000000000AAE66B6446Eab63D0992A9741058", chain="Ethereum", kind="nft_marketplace", protocol="OpenSea"),
    dict(name="GMXExchange", address=None, chain="Ethereum", kind="perp_dex", protocol="GMX"),
    dict(name="KyberSwapPool", address="0x9ac6cdfe2aa434fb7487aa37ba4c6ffcd6eaa91a", chain="Ethereum", kind="dex", protocol="KyberSwap"),
    # --- exploit-target protocols (historical) ---
    dict(name="RoninBridge", address="0xe6f7565a24e747582e0b7b05e1a64a8f293041e4", chain="Ronin", kind="bridge", protocol="Ronin"),
    dict(name="PolyBridge", address=None, chain="BSC", kind="bridge", protocol="PolyNetwork"),
    dict(name="WormholeNft", address="wormhole:attestation", chain="Solana", kind="bridge", protocol="Wormhole"),
    dict(name="bZx", address=None, chain="Ethereum", kind="leverage", protocol="bZx"),
    dict(name="CreamFinance", address="0xd5475b4938ff176713304592703bee0402a7149e", chain="Ethereum", kind="lending", protocol="Cream Finance"),
    dict(name="MangoMarkets", address="MangoCzJ36AjEerPj49L3F72ZfxLwCgEj9An6429e", chain="Solana", kind="perp_dex", protocol="Mango Markets"),
    dict(name="Beanstalk", address="0x123F1BE8914278471b82132F8F8614B5255212FC", chain="Ethereum", kind="yield", protocol="Beanstalk"),
    dict(name="EulerFinance", address="0x27327c5bbf2f9ce874ba2c2949c63a130d863a42", chain="Ethereum", kind="lending", protocol="Euler Finance"),
]

