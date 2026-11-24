.pragma library
// The server list's order rule (device round of 142, iPhone Air: between a look at the list and the tap the rows
// re-sorted on a latency update, and a tap aimed at «Финляндия 1» selected «Эстония 2»). A look cannot be detected,
// so the order is not tied to touches: the page takes it when it opens (or on the person's own act that changes what
// the rows mean - the transport mode) and keeps it while it is on screen. Values inside the rows update in place.
//   shown  - the row keys in the order on screen ([] = nothing shown yet)
//   sorted - the keys of the rows that exist now, in the sort order
// Returns the order to show: the shown rows that still exist keep their places, a row that left is dropped, a row that
// is new goes after them (in its sorted order). Pure; tests: core/serviceEngine/tests/check_server_list_order.sh.
function keepShownOrder(shown, sorted) {
    const present = {}
    for (let i = 0; i < sorted.length; ++i)
        present[sorted[i]] = true
    const out = []
    const taken = {}
    for (let i = 0; i < shown.length; ++i) {
        const k = shown[i]
        if (present[k] === true && taken[k] !== true) {
            out.push(k)
            taken[k] = true
        }
    }
    for (let i = 0; i < sorted.length; ++i) {
        const k = sorted[i]
        if (taken[k] !== true) {
            out.push(k)
            taken[k] = true
        }
    }
    return out
}

// The same keys in the same order (the model is replaced only when the order really changes: a new array resets the
// ListView and recreates every row, the one under a finger included).
function sameOrder(a, b) {
    if (a.length !== b.length)
        return false
    for (let i = 0; i < a.length; ++i)
        if (a[i] !== b[i])
            return false
    return true
}
