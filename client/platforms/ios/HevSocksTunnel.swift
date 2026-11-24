import HevSocks5Tunnel
import NetworkExtension

public enum Socks5Tunnel {

    private static var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    private static var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else {
                return nil
            }
            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize
            )
            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    @discardableResult
    public static func run(withConfig filePath: String) -> Int32 {
        guard let fileDescriptor = self.tunnelFileDescriptor else {
            fatalError("Get tunnel file descriptor failed.")
        }
        return hev_socks5_tunnel_main(filePath.cString(using: .utf8), fileDescriptor)
    }

    public static func quit() {
        hev_socks5_tunnel_quit()
    }

    // AVPN (review R43 F1): the non-blocking stop of recipes/hev-socks5-tunnel patch 0001 (quit() above waits for hev's
    // event fd without a bound - never call it from a stop). 0 = queued, -EAGAIN = hev still initialising (the request
    // is kept and hev quits as it starts running), another negative errno = refused.
    public static func tryQuit() -> Int32 {
        hev_socks5_tunnel_try_quit()
    }
}

// AVPN (review R43 F1): the live hev for XrayHevStop (XraySocketCallbackLifecycle.swift).
struct LiveHevControl: XrayHevControl {
    func tryQuit() -> Int32 { Socks5Tunnel.tryQuit() }
    func quitBlocking() { Socks5Tunnel.quit() }
}
