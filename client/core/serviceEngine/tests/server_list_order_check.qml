// Device round of 142 (A4): the server list's order rule (ui/qml/Tribe/ServerListOrder.js), by behaviour.
// Run headless by check_server_list_order.sh: `qml` offscreen, exit code = the number of failed checks.
import QtQuick
import "../../../ui/qml/Tribe/ServerListOrder.js" as ServerListOrder

QtObject {
    property int failed: 0
    property int checks: 0
    function eq(got, want, what) {
        checks += 1
        if (JSON.stringify(got) !== JSON.stringify(want)) {
            failed += 1
            console.log("FAIL " + what + ": got " + JSON.stringify(got) + ", want " + JSON.stringify(want))
        }
    }
    Component.onCompleted: {
        const keep = ServerListOrder.keepShownOrder
        // the device case: Финляндия 1 first at open; a latency update sorts Эстония 2 above it - the shown order stays
        eq(keep(["fi1", "ee2", "de1", "ee3"], ["ee2", "ee3", "fi1", "de1"]), ["fi1", "ee2", "de1", "ee3"],
           "a latency update keeps the order on screen")
        // nothing shown yet (the page opens): the sort order
        eq(keep([], ["ee2", "ee3", "fi1"]), ["ee2", "ee3", "fi1"], "the first order is the sort order")
        // a server that left is dropped, the others keep their order
        eq(keep(["fi1", "ee2", "de1", "ee3"], ["ee3", "de1", "fi1"]), ["fi1", "de1", "ee3"], "a row that left is dropped")
        // a new server joins after the shown ones (in its sorted order), never between them
        eq(keep(["fi1", "ee2"], ["nl1", "ee2", "pl1", "fi1"]), ["fi1", "ee2", "nl1", "pl1"], "new rows join at the end")
        // both at once
        eq(keep(["fi1", "ee2", "de1"], ["us1", "de1", "fi1"]), ["fi1", "de1", "us1"], "left and joined at once")
        // a duplicate key in either list is shown once
        eq(keep(["fi1", "fi1", "ee2"], ["ee2", "fi1", "ee2"]), ["fi1", "ee2"], "a key is shown once")
        // nothing exists any more
        eq(keep(["fi1", "ee2"], []), [], "an empty pool empties the list")
        // the inputs are not changed
        const shown = ["fi1", "ee2"], sorted = ["ee2", "fi1", "de1"]
        keep(shown, sorted)
        eq([shown, sorted], [["fi1", "ee2"], ["ee2", "fi1", "de1"]], "the inputs stay as they were")

        const same = ServerListOrder.sameOrder
        eq(same(["a", "b"], ["a", "b"]), true, "sameOrder: same keys, same order")
        eq(same(["a", "b"], ["b", "a"]), false, "sameOrder: another order")
        eq(same(["a"], ["a", "b"]), false, "sameOrder: another length")
        eq(same([], []), true, "sameOrder: both empty")

        console.log("server_list_order_check: " + (failed ? failed + " of " + checks + " checks FAILED" : "OK (" + checks + " checks)"))
        Qt.exit(failed)
    }
}
