// AVPN serviceEngine — login-free MTProto-проба «Telegram реально работает на этой ноде». [чистая логика — тестируема]
//
// Зачем: в РФ Telegram чаще НЕ блокируют, а ДУШАТ (DPI-троттлинг по SNI/IP) — TCP+TLS проходят, но
// сообщения не грузятся. Поэтому reachability («200 OK») = ложно-зелёный. Сильный сигнал «DC реально
// говорит по MTProto через этот туннель прямо сейчас» — выполнить начало handshake генерации auth_key:
// послать req_pq_multi (БЕЗ логина/аккаунта, auth_key_id=0) и дождаться resPQ с эхом нашего nonce.
// Получили корректный resPQ ⇒ дата-плейн DC жив. (Goodput-замер троттлинга — отдельным сэмплом в раннере.)
//
// Этот класс — ЧИСТЫЙ кодек (билд запроса + разбор ответа), без сети. Сокет к seed-DC-IP и таймауты —
// в ServiceProbe.cpp (QTcpSocket/NWConnection). Транспорт: intermediate (тег 0xeeeeeeee один раз при
// коннекте, далее каждый пакет = 4-байтный LE-префикс длины + payload) — без обфускации, к незаблоченному
// DC её не нужно. Источники: core.telegram.org/mtproto/auth_key (req_pq_multi#be7e8ef1, resPQ#05162463),
// /mtproto/serialize (unencrypted message: auth_key_id:long=0, message_id:long, message_data_length:int, data).
#pragma once

#include <QByteArray>

namespace avpn {

class MtprotoProbe {
public:
    // TL-конструкторы (host-endian uint32; на проводе сериализуются LE).
    static constexpr quint32 kReqPqMulti = 0xbe7e8ef1u; // req_pq_multi#be7e8ef1 nonce:int128 = ResPQ
    static constexpr quint32 kResPq      = 0x05162463u; // resPQ#05162463 nonce server_nonce pq fingerprints
    // Тег коннекта intermediate-транспорта (шлётся один раз перед первым пакетом).
    static constexpr quint32 kIntermediateTag = 0xeeeeeeeeu;

    static constexpr int kNonceLen = 16; // int128

    // Собрать unencrypted message req_pq_multi: auth_key_id=0(8) + msgId(8) + len(4) + ctor(4) + nonce(16).
    // nonce16 — ровно 16 случайных байт (его эхо проверяем в ответе). msgId — валидный msg_id (caller: ~unixtime<<32, %4==0).
    static QByteArray buildReqPqMulti(const QByteArray &nonce16, qint64 msgId)
    {
        QByteArray data;                    // message_data = ctor + nonce
        appendLe32(data, kReqPqMulti);
        data.append(nonce16.left(kNonceLen));

        QByteArray out;
        appendLe64(out, 0);                 // auth_key_id = 0 (unencrypted)
        appendLe64(out, quint64(msgId));    // message_id
        appendLe32(out, quint32(data.size())); // message_data_length (= 20)
        out.append(data);
        return out;
    }

    // Обернуть payload в intermediate-фрейм: 4-байтный LE-префикс длины + payload.
    static QByteArray frameIntermediate(const QByteArray &payload)
    {
        QByteArray out;
        appendLe32(out, quint32(payload.size()));
        out.append(payload);
        return out;
    }

    // Разобрать unencrypted message ответа (уже без intermediate-длины). true ⇒ это resPQ с НАШИМ nonce.
    // Раскладка: auth_key_id=0(8) + msgId(8) + len(4) + resPQ-ctor(4) + nonce(16) + server_nonce(16) + …
    // Для liveness достаточно проверить auth_key_id=0, конструктор и эхо nonce; server_nonce отдаём наружу.
    static bool parseResPq(const QByteArray &msg, const QByteArray &expectedNonce, QByteArray *outServerNonce)
    {
        // минимум: 8+8+4 + 4(ctor) + 16(nonce) + 16(server_nonce) = 56
        if (msg.size() < 56 || expectedNonce.size() != kNonceLen)
            return false;
        for (int i = 0; i < 8; ++i)             // auth_key_id должен быть 0 (unencrypted)
            if (msg[i] != 0) return false;
        if (le32(msg, 20) != kResPq)            // конструктор resPQ
            return false;
        if (msg.mid(24, kNonceLen) != expectedNonce) // nonce должен совпасть с отправленным
            return false;
        if (outServerNonce)
            *outServerNonce = msg.mid(40, kNonceLen);
        return true;
    }

private:
    static void appendLe32(QByteArray &b, quint32 v)
    {
        b.append(char(v & 0xff)); b.append(char((v >> 8) & 0xff));
        b.append(char((v >> 16) & 0xff)); b.append(char((v >> 24) & 0xff));
    }
    static void appendLe64(QByteArray &b, quint64 v)
    {
        for (int i = 0; i < 8; ++i) b.append(char((v >> (8 * i)) & 0xff));
    }
    static quint32 le32(const QByteArray &b, int off)
    {
        return quint32(quint8(b[off])) | (quint32(quint8(b[off + 1])) << 8)
               | (quint32(quint8(b[off + 2])) << 16) | (quint32(quint8(b[off + 3])) << 24);
    }
};

} // namespace avpn
