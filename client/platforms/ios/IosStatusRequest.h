#pragma once
#include <cstdint>
#include <mutex>
#include <optional>

// A completion and its deadline compete for the same ticket. Retrying within the same NE
// session gets a new ID, so a late response cannot finish or update the next request.
class IosStatusRequest {
public:
    std::optional<std::uint64_t> begin(std::uint64_t session) {
        std::lock_guard<std::mutex> lock(mutex);
        if (pending) return std::nullopt;
        pending = true;
        epoch = session;
        return ++id;
    }
    bool complete(std::uint64_t session, std::uint64_t request) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!pending || epoch != session || id != request) return false;
        pending = false;
        return true;
    }
    void invalidate() {
        std::lock_guard<std::mutex> lock(mutex);
        ++id;
        pending = false;
    }
    std::uint64_t requestId() const {
        std::lock_guard<std::mutex> lock(mutex);
        return id;
    }
private:
    mutable std::mutex mutex;
    std::uint64_t epoch = 0, id = 0;
    bool pending = false;
};
