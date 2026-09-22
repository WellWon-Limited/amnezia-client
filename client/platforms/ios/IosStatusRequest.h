#pragma once
#include <cstdint>
#include <mutex>
#include <optional>

// A completion and its deadline compete for the same ticket. Retrying within the same NE
// session gets a new ID, so a late response cannot finish or update the next request.
//
// AVPN (фикс-волна 2026-09-22, C5/H7): два РАЗНЫХ вопроса, раньше склеенных в complete():
//  1. Владение заявкой (exactly-once): кто освобождает слот — ответ, nil-колбэк или дедлайн 3 с.
//     Это complete(): ровно один победитель, после него можно начать следующую заявку.
//  2. Применение полезной нагрузки: ответ NE, пришедший ПОСЛЕ дедлайна своей заявки, всё равно
//     несёт свежие handshake/rx/tx (во время роуминга ответ идёт через workQueue адаптера и легко
//     опаздывает на 3 с). Раньше такой ответ выбрасывался целиком → handshake=0 → ложный DEAD.
//     Это accept(): применяем ответ сессии `session`, если его request новее последнего
//     применённого (request > lastApplied). Старый ответ, обогнанный более новым, отвергается —
//     монотонность данных сохраняется.
class IosStatusRequest {
public:
    std::optional<std::uint64_t> begin(std::uint64_t session) {
        std::lock_guard<std::mutex> lock(mutex);
        if (pending) return std::nullopt;
        pending = true;
        if (epoch != session) {
            epoch = session;
            lastApplied = 0; // новая сессия — своя шкала применённых ответов
        }
        return ++id;
    }
    bool complete(std::uint64_t session, std::uint64_t request) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!pending || epoch != session || id != request) return false;
        pending = false;
        return true;
    }
    // Можно ли применить полезную нагрузку ответа (независимо от того, кто выиграл complete()).
    bool accept(std::uint64_t session, std::uint64_t request) {
        std::lock_guard<std::mutex> lock(mutex);
        if (epoch != session || request == 0 || request > id || request <= lastApplied
            || request <= invalidatedThrough) return false;
        lastApplied = request;
        return true;
    }
    void invalidate() {
        std::lock_guard<std::mutex> lock(mutex);
        ++id;
        invalidatedThrough = id; // ответы на все выданные до сих пор заявки больше не применимы
        pending = false;
    }
    std::uint64_t requestId() const {
        std::lock_guard<std::mutex> lock(mutex);
        return id;
    }
private:
    mutable std::mutex mutex;
    std::uint64_t epoch = 0, id = 0, lastApplied = 0, invalidatedThrough = 0;
    bool pending = false;
};
