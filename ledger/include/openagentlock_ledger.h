/* openagentlock_ledger.h — C ABI over ledger/src/ffi.rs.
 *
 * Hand-rolled header (not cbindgen-generated) — thin surface, easier to
 * keep in sync manually than to drag cbindgen into the build. If the
 * surface grows, switch to cbindgen.
 *
 * Returns: 1 on success, 0 on failure. Callers own every buffer.
 */

#ifndef OPENAGENTLOCK_LEDGER_H
#define OPENAGENTLOCK_LEDGER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* oal_leaf_hash
 *   prev_leaf — MUST be non-NULL and point to exactly 32 readable bytes.
 *   out       — MUST be non-NULL and point to 32 writable bytes.
 *   payload_hash / sig — may be NULL iff their length is 0.
 * Returns 1 on success, 0 when prev_leaf or out is NULL (no write occurs).
 */
uint8_t oal_leaf_hash(
    const uint8_t* payload_hash,
    size_t payload_hash_len,
    const uint8_t* sig,
    size_t sig_len,
    const uint8_t* prev_leaf,
    uint8_t* out
);

/* oal_merkle_root
 *   leaves — points to exactly count * 32 readable bytes, packed. May be
 *            NULL iff count == 0.
 *   out    — MUST be non-NULL and point to 32 writable bytes.
 * When count == 0, `out` receives sha256("") (canonical empty-tree root).
 * Returns 1 on success, 0 when out is NULL (no write occurs).
 */
uint8_t oal_merkle_root(
    const uint8_t* leaves,
    size_t count,
    uint8_t* out
);

/* oal_verify_proof
 *   leaf / root — MUST each be non-NULL and point to 32 readable bytes.
 *   proof       — points to proof_len * 32 readable bytes. May be NULL
 *                 iff proof_len == 0.
 *   index       — leaf position in the original tree; passing a value
 *                 larger than the tree implied by proof_len returns 0.
 * Returns 1 when the proof reconstructs `root` from `leaf` at `index`,
 * 0 otherwise (also 0 on any NULL buffer or length violation — never
 * invokes undefined behaviour).
 */
uint8_t oal_verify_proof(
    const uint8_t* leaf,
    size_t index,
    const uint8_t* proof,
    size_t proof_len,
    const uint8_t* root
);

#ifdef __cplusplus
}
#endif

#endif /* OPENAGENTLOCK_LEDGER_H */
