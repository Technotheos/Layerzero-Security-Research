# Layerzero-Security-Research

**Description :**
The LayerZero V2 implementation on the TON blockchain utilizes a custom circular buffer structure, DeterministicInsertionCircularQueue.fc, to manage message nonces and packet storage. This structure is implemented as a deterministic quad-tree with a fixed capacity (typically 1024 slots) to ensure predictable gas costs and state management.

**The Vulnerability :** A critical vulnerability exists in the _setRaw internal function of the circular queue. The contract calculates the storage index (slot) for a given message nonce using a raw modulo operation: int slot = key % MAX_CELL_BITS; Crucially, the implementation fails to validate the "distance" between the incoming nonce and the last executed/processed nonce. It also lacks a check to see if a storage slot is already occupied before performing a write operation.

**The Attack (Nonce Lapping) :** An attacker can exploit this by "lapping" the buffer. By committing a nonce exactly N + 1024 (where N is a pending, unexecuted nonce), the contract resolves both nonces to the same physical storage slot. Because there is no "Safety Guard" or head-tail collision check, the contract executes a DICTISET (or the equivalent quad-tree path replacement) that physically overwrites the unexecuted metadata of Nonce N with the data from Nonce N+1024.

**Impact :**
1.Permanent Channel DoS (Bricking) : Once a pending nonce is overwritten, the execution sequence is broken. The contract can no longer retrieve the original packet data for the earlier nonce, causing all future attempts to progress the channel to fail with a TVM exception.

2.Structural State Corruption : In the production quad-tree implementation, this overwrite can replace internal branch references with leaf data, leading to a "No more references" error that fundamentally breaks the contract's storage navigation.

3.Permanent Locking of Funds : Any funds associated with the overwritten nonce (e.g., in an OFT transfer) are rendered unclaimable, as the proof of their existence is deleted from the contract state.
