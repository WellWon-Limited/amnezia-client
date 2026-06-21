// AVPN serviceEngine — тест чистой логики ранжирования нод для шторки выбора (кроссплатформенно).
// Палочки = SignalQuality::barsForRtt; порядок в шторке = быстрые ВНИЗУ, неизмеренные сверху.
#include "../NodeRanking.h"

#include <QList>
#include <QString>
#include <cstdio>

using namespace avpn;

static int g_failures = 0;
#define CHECK(cond, msg)                                                                            \
    do {                                                                                            \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_failures; }                              \
        else { std::printf("ok:   %s\n", msg); }                                                    \
    } while (0)

int main()
{
    // Сортировка: top→bottom = [неизмеренные] , затем по убыванию rtt (быстрые ВНИЗУ).
    {
        QList<RankRow> in;
        in.append({ QStringLiteral("A"), 200 });
        in.append({ QStringLiteral("B"), -1 });   // неизмеренная
        in.append({ QStringLiteral("C"), 50 });   // самая быстрая
        in.append({ QStringLiteral("D"), 120 });
        const QList<RankRow> out = rankFastestAtBottom(in);
        CHECK(out.size() == 4, "size 4");
        CHECK(out[0].nodeId == "B", "unknown -> top");
        CHECK(out[1].nodeId == "A", "slowest measured below unknown");
        CHECK(out[2].nodeId == "D", "middle");
        CHECK(out[3].nodeId == "C", "fastest -> bottom");
    }

    // RTT→палочки (щедрая VPN-шкала из SignalQuality).
    CHECK(barsForNode(50) == 5, "50ms = 5 bars");
    CHECK(barsForNode(120) == 5, "120ms = 5 bars");
    CHECK(barsForNode(200) == 4, "200ms = 4 bars");
    CHECK(barsForNode(-1) == 0, "unknown = 0 bars");

    // Стабильность: равные rtt и группа неизмеренных сохраняют исходный порядок.
    {
        QList<RankRow> in;
        in.append({ QStringLiteral("U1"), -1 });
        in.append({ QStringLiteral("U2"), -1 });
        in.append({ QStringLiteral("E1"), 100 });
        in.append({ QStringLiteral("E2"), 100 });
        const QList<RankRow> out = rankFastestAtBottom(in);
        CHECK(out[0].nodeId == "U1" && out[1].nodeId == "U2", "unknowns keep input order");
        CHECK(out[2].nodeId == "E1" && out[3].nodeId == "E2", "equal rtt keep input order");
    }

    // fastestMeasuredNodeId: nodeId с минимальным rtt>=0 (для авто-выбора «Авто быстрейший»); "" если нет.
    {
        QList<RankRow> in;
        in.append({ QStringLiteral("A"), 200 });
        in.append({ QStringLiteral("B"), -1 });
        in.append({ QStringLiteral("C"), 50 });
        in.append({ QStringLiteral("D"), 120 });
        CHECK(fastestMeasuredNodeId(in) == "C", "fastest measured = C (50ms)");
    }
    {
        QList<RankRow> in; // все неизмерены → пусто (фолбэк на weight в движке)
        in.append({ QStringLiteral("U1"), -1 });
        in.append({ QStringLiteral("U2"), -1 });
        CHECK(fastestMeasuredNodeId(in).isEmpty(), "all unknown -> empty (fallback)");
    }
    {
        QList<RankRow> in; // ничья rtt → стабильно первый
        in.append({ QStringLiteral("E1"), 100 });
        in.append({ QStringLiteral("E2"), 100 });
        CHECK(fastestMeasuredNodeId(in) == "E1", "tie -> first wins (stable)");
    }

    if (g_failures) { std::printf("\n%d FAILURES\n", g_failures); return 1; }
    std::printf("\nALL PASS\n");
    return 0;
}
