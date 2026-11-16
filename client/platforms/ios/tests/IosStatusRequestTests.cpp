#include "../IosStatusRequest.h"
#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

int main() {
    IosStatusRequest gate;
    auto first = gate.begin(1);
    assert(first && !gate.begin(1));
    assert(gate.complete(1, *first)); // deadline wins, allowing a retry
    auto second = gate.begin(1);
    assert(second && *second != *first);
    assert(!gate.complete(1, *first)); // late nil/response cannot release the new request
    assert(!gate.begin(1));
    gate.invalidate(); // stop/reconnect cancels an outstanding response
    auto third = gate.begin(2);
    assert(third && !gate.complete(1, *second));
    assert(!gate.complete(1, *third)); // correct request ID, wrong session
    assert(gate.complete(2, *third));
    assert(!gate.complete(2, *third));
    for (unsigned epoch = 3; epoch < 503; ++epoch) {
        auto ticket = gate.begin(epoch);
        assert(ticket);
        std::atomic_int completed {0};
        std::vector<std::thread> racers;
        for (int i = 0; i < 4; ++i)
            racers.emplace_back([&] { if (gate.complete(epoch, *ticket)) ++completed; });
        for (auto &thread : racers) thread.join();
        assert(completed == 1); // response/sendError/deadline/double callback: exactly once
    }
    // AVPN (iOS data watch, 141): lastAppliedIs - the second consumer of a reply sees only the reply accept()
    // let through; a newer accepted reply, an invalidation or another session hide it.
    {
        IosStatusRequest g;
        auto a = g.begin(7);
        assert(a && !g.lastAppliedIs(7, *a)); // not applied yet
        assert(g.complete(7, *a) && g.accept(7, *a));
        assert(g.lastAppliedIs(7, *a));
        assert(!g.lastAppliedIs(8, *a)); // other session
        auto b = g.begin(7);
        assert(b && g.complete(7, *b) && g.accept(7, *b));
        assert(!g.lastAppliedIs(7, *a) && g.lastAppliedIs(7, *b)); // superseded by a newer reply
        g.invalidate();
        assert(!g.lastAppliedIs(7, *b)); // a snapshot request cancels what was applied before it
        auto c = g.begin(7);
        assert(c && !g.accept(7, *b) && g.accept(7, *c) && g.lastAppliedIs(7, *c));
        assert(!g.lastAppliedIs(7, 0));
    }
    std::cout << "IosStatusRequestTests: 500 competing completion races passed\n";
}
