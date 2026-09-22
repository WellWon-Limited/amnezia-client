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
    std::cout << "IosStatusRequestTests: 500 competing completion races passed\n";
}
