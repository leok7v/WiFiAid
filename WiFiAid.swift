import Foundation
import Combine
import SwiftUI
import Darwin
#if os(macOS)
import CoreWLAN
#endif

@inline(__always)
nonisolated func nowNs() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_UPTIME_RAW, &ts)
    return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
}

nonisolated func msFromNs(_ ns: UInt64) -> Double { Double(ns) / 1_000_000 }

nonisolated struct IPv4: Hashable, Sendable, CustomStringConvertible {

    let raw: UInt32

    init(_ n: UInt32) { self.raw = n }

    init?(_ s: String) {
        var a = in_addr()
        guard inet_pton(AF_INET, s, &a) == 1 else {
            return nil
        }
        self.raw = a.s_addr
    }

    var addr: in_addr { in_addr(s_addr: raw) }

    var description: String {
        var a = in_addr(s_addr: raw)
        var buf = [CChar](
            repeating: 0, count: Int(INET_ADDRSTRLEN)
        )
        _ = inet_ntop(
            AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN)
        )
        return String(cString: buf)
    }
}

nonisolated private enum RT {
    static let HDR_SIZE   = 92   // sizeof(rt_msghdr)
    static let OFF_LEN    = 0    // u_short rtm_msglen
    static let OFF_IDX    = 4    // u_short rtm_index
    static let OFF_FLAGS  = 8    // int     rtm_flags
    static let OFF_ADDRS  = 12   // int     rtm_addrs
    static let SDL_INDEX  = 2
    static let SDL_NLEN   = 5
    static let SDL_ALEN   = 6
    static let SDL_DATA   = 8
    static let F_GATEWAY:  Int32 = 0x2
    static let F_LLINFO:   Int32 = 0x400
    static let A_DST:      Int32 = 0x1
    static let A_GATEWAY:  Int32 = 0x2
    static let NRT_DUMP:   Int32 = 1
    static let NRT_FLAGS:  Int32 = 2
}

nonisolated func saRoundup(_ n: Int) -> Int {
    let u = MemoryLayout<UInt32>.size
    return n > 0 ? (1 + ((n - 1) | (u - 1))) : u
}

nonisolated func walkSockaddrs(
    after hdr: UnsafeRawPointer, addrs: Int32
) -> [Int: UnsafeRawPointer] {
    var out: [Int: UnsafeRawPointer] = [:]
    var cur = hdr.advanced(by: RT.HDR_SIZE)
    for i in 0..<8 {
        if (addrs & (1 << i)) == 0 { continue }
        let sa = cur.assumingMemoryBound(to: sockaddr.self)
        out[i] = cur
        let saLen = max(
            Int(sa.pointee.sa_len),
            MemoryLayout<UInt32>.size
        )
        cur = cur.advanced(by: saRoundup(saLen))
    }
    return out
}

nonisolated func saToIPv4(_ p: UnsafeRawPointer) -> IPv4? {
    let sa = p.assumingMemoryBound(to: sockaddr.self)
    guard sa.pointee.sa_family == UInt8(AF_INET) else { return nil }
    let sin = p.assumingMemoryBound( to: sockaddr_in.self )
    return IPv4(sin.pointee.sin_addr.s_addr)
}

nonisolated func saIsV4Zero(_ p: UnsafeRawPointer) -> Bool {
    let sa = p.assumingMemoryBound(to: sockaddr.self)
    if sa.pointee.sa_family == UInt8(AF_INET) {
        let sin = p.assumingMemoryBound(to: sockaddr_in.self)
        return sin.pointee.sin_addr.s_addr == 0
    }
    return sa.pointee.sa_len <= 2
}

nonisolated func ifaceName(index: UInt16) -> String? {
    var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
    guard if_indextoname(UInt32(index), &buf) != nil else {
        return nil
    }
    return String(cString: buf)
}

nonisolated struct IfaceAddrs: Sendable {
    let ipv4: IPv4
    let mask: IPv4
}

nonisolated func ifaceAddrs(name: String) -> IfaceAddrs? {
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let head = ifap else {
        return nil
    }
    defer { freeifaddrs(ifap) }
    var p: UnsafeMutablePointer<ifaddrs>? = head
    while let cur = p {
        let n = String(cString: cur.pointee.ifa_name)
        let fam = cur.pointee.ifa_addr?
            .pointee.sa_family ?? 0
        if n == name, fam == UInt8(AF_INET),
           let ap = cur.pointee.ifa_addr {
            let ip = ap.withMemoryRebound(
                to: sockaddr_in.self, capacity: 1
            ) { IPv4($0.pointee.sin_addr.s_addr) }
            var mask = IPv4(0x00FFFFFF)
            if let mp = cur.pointee.ifa_netmask {
                mask = mp.withMemoryRebound(
                    to: sockaddr_in.self, capacity: 1
                ) { IPv4($0.pointee.sin_addr.s_addr) }
            }
            return IfaceAddrs(ipv4: ip, mask: mask)
        }
        p = cur.pointee.ifa_next
    }
    return nil
}

nonisolated struct IfaceStats: Sendable {
    let ibytes: UInt64
    let obytes: UInt64
    let ierrors: UInt64
    let oerrors: UInt64
    let ts: UInt64
}

nonisolated func ifaceStats(name: String) -> IfaceStats? {
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let head = ifap else {
        return nil
    }
    defer { freeifaddrs(ifap) }
    var p: UnsafeMutablePointer<ifaddrs>? = head
    while let cur = p {
        let n = String(cString: cur.pointee.ifa_name)
        let fam = cur.pointee.ifa_addr?
            .pointee.sa_family ?? 0
        if n == name, fam == UInt8(AF_LINK),
           let dp = cur.pointee.ifa_data {
            let d = dp.assumingMemoryBound(
                to: if_data.self
            )
            return IfaceStats(
                ibytes: UInt64(d.pointee.ifi_ibytes),
                obytes: UInt64(d.pointee.ifi_obytes),
                ierrors: UInt64(d.pointee.ifi_ierrors),
                oerrors: UInt64(d.pointee.ifi_oerrors),
                ts: nowNs()
            )
        }
        p = cur.pointee.ifa_next
    }
    return nil
}

nonisolated struct RouteInfo: Sendable {
    let interface: String
    let selfIP: IPv4
    let gateway: IPv4
    let mask: IPv4
}

nonisolated func discoverDefaultRoutes() -> [RouteInfo] {
    var mib: [Int32] = [
        CTL_NET, PF_ROUTE, 0, AF_INET, RT.NRT_DUMP, 0,
    ]
    var len = 0
    guard sysctl(&mib, 6, nil, &len, nil, 0) == 0 else { return [] }
    let buf = UnsafeMutableRawPointer.allocate(
        byteCount: len, alignment: 8
    )
    defer { buf.deallocate() }
    guard sysctl(&mib, 6, buf, &len, nil, 0) == 0 else { return [] }
    var off = 0
    var out: [RouteInfo] = []
    var seen = Set<String>()
    while off < len {
        let hdr = UnsafeRawPointer(buf.advanced(by: off))
        let msgLen = Int(hdr.load(
            fromByteOffset: RT.OFF_LEN, as: UInt16.self
        ))
        if msgLen == 0 { break }
        let flags = hdr.load(
            fromByteOffset: RT.OFF_FLAGS, as: Int32.self
        )
        let addrs = hdr.load(
            fromByteOffset: RT.OFF_ADDRS, as: Int32.self
        )
        if (flags & RT.F_GATEWAY) != 0,
           (addrs & RT.A_DST) != 0,
           (addrs & RT.A_GATEWAY) != 0 {
            let sas = walkSockaddrs(after: hdr, addrs: addrs)
            if let dstP = sas[0], let gwP = sas[1],
               saIsV4Zero(dstP),
               let gw = saToIPv4(gwP) {
                let idx = hdr.load(
                    fromByteOffset: RT.OFF_IDX, as: UInt16.self
                )
                let name = ifaceName(index: idx) ?? "en0"
                let key = "\(name)|\(gw.raw)"
                if !seen.contains(key) {
                    seen.insert(key)
                    let ia = ifaceAddrs(name: name)
                    out.append(RouteInfo(
                        interface: name,
                        selfIP: ia?.ipv4 ?? IPv4(0),
                        gateway: gw,
                        mask: ia?.mask ?? IPv4(0x00FFFFFF)
                    ))
                }
            }
        }
        off += msgLen
    }
    return out
}

nonisolated func discoverDefaultRoute() -> RouteInfo? {
    discoverDefaultRoutes().first
}

nonisolated func discoverPrimaryDNS() -> IPv4? {
    guard let txt = try? String(
        contentsOfFile: "/etc/resolv.conf", encoding: .utf8
    ) else {
        return nil
    }
    for line in txt.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("nameserver") {
            let parts = trimmed.split(
                separator: " ", omittingEmptySubsequences: true
            )
            if parts.count >= 2, let ip = IPv4(String(parts[1])) {
                return ip
            }
        }
    }
    return nil
}

nonisolated struct ArpEntry: Sendable {
    let ip: IPv4
    let mac: [UInt8]
    let ifname: String
}

nonisolated func dumpArpTable() -> [ArpEntry] {
    var mib: [Int32] = [
        CTL_NET, PF_ROUTE, 0, AF_INET, RT.NRT_FLAGS,
        RT.F_LLINFO,
    ]
    var len = 0
    guard sysctl(&mib, 6, nil, &len, nil, 0) == 0 else { return [] }
    let buf = UnsafeMutableRawPointer.allocate(
        byteCount: len, alignment: 8
    )
    defer { buf.deallocate() }
    guard sysctl(&mib, 6, buf, &len, nil, 0) == 0 else { return [] }
    var out: [ArpEntry] = []
    var off = 0
    while off < len {
        let hdr = UnsafeRawPointer(buf.advanced(by: off))
        let msgLen = Int(hdr.load(
            fromByteOffset: RT.OFF_LEN, as: UInt16.self
        ))
        if msgLen == 0 { break }
        let after = hdr.advanced(by: RT.HDR_SIZE)
        let sin = after.assumingMemoryBound(to: sockaddr_in.self)
        let ip = IPv4(sin.pointee.sin_addr.s_addr)
        let sinLen = max(
            Int(sin.pointee.sin_len), MemoryLayout<UInt32>.size
        )
        let dl = after.advanced(by: saRoundup(sinLen))
        let alen = dl.load(
            fromByteOffset: RT.SDL_ALEN, as: UInt8.self
        )
        if alen == 6 {
            let nlen = Int(dl.load(
                fromByteOffset: RT.SDL_NLEN, as: UInt8.self
            ))
            let mac = readMac(dl: dl, nlen: nlen)
            let idx = dl.load(
                fromByteOffset: RT.SDL_INDEX, as: UInt16.self
            )
            let name = ifaceName(index: idx) ?? ""
            out.append(ArpEntry(ip: ip, mac: mac, ifname: name))
        }
        off += msgLen
    }
    return out
}

nonisolated func readMac(dl: UnsafeRawPointer, nlen: Int) -> [UInt8] {
    // sockaddr_dl header is 8 bytes; sdl_data follows.
    // The interface name occupies the first nlen bytes of
    // sdl_data; the MAC address follows for alen bytes.
    let raw = dl.advanced(by: RT.SDL_DATA + nlen)
    var mac = [UInt8](repeating: 0, count: 6)
    for i in 0..<6 {
        mac[i] = raw.load(fromByteOffset: i, as: UInt8.self)
    }
    return mac
}

nonisolated func subnet24(from ip: IPv4, exclude: Set<UInt32>) -> [IPv4] {
    let parts = ip.description.split(separator: ".")
    guard parts.count == 4 else { return [] }
    let pre = parts[0..<3].joined(separator: ".")
    var out: [IPv4] = []
    for o in 1..<255 {
        guard let v = IPv4("\(pre).\(o)") else { continue }
        if v.raw == ip.raw { continue }
        if exclude.contains(v.raw) { continue }
        out.append(v)
    }
    return out
}


nonisolated func buildICMPEcho(seq: UInt16, payloadSize: Int = 16) -> [UInt8] {
    var p = [UInt8](repeating: 0, count: 8 + payloadSize)
    p[0] = 8
    p[6] = UInt8(seq >> 8)
    p[7] = UInt8(seq & 0xFF)
    for i in 0..<payloadSize {
        p[8 + i] = UInt8((i + Int(seq)) & 0xFF)
    }
    let c = icmpChecksum(p)
    p[2] = UInt8(c >> 8)
    p[3] = UInt8(c & 0xFF)
    return p
}

nonisolated func icmpChecksum(_ d: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < d.count {
        let w = UInt16(d[i]) << 8 | UInt16(d[i + 1])
        sum &+= UInt32(w)
        i += 2
    }
    if i < d.count {
        sum &+= UInt32(UInt16(d[i]) << 8)
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}

nonisolated final class ICMPProber: @unchecked Sendable {
    struct Sample: Sendable {
        let sendNs: UInt64
        let rttNs: UInt64?
        let seq: UInt16
    }

    private struct TargetState {
        var nextSeq: UInt16 = 0
        var inflight: [UInt16: UInt64] = [:]
        let maxInflight: Int
    }

    private let fd: Int32
    private let queue = DispatchQueue(
        label: "wifi.probe", qos: .userInitiated
    )
    private var recvSource: DispatchSourceRead?
    private var sendTimer: DispatchSourceTimer?
    private let lock = NSLock()
    private var targets: [UInt32: TargetState] = [:]
    var onSample: (@Sendable (IPv4, Sample) -> Void)?

    init() throws {
        let f = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        if f < 0 {
            let code = POSIXErrorCode(rawValue: errno) ?? .EINVAL
            throw POSIXError(code)
        }
        fd = f
        let fl = fcntl(f, F_GETFL, 0)
        _ = fcntl(f, F_SETFL, fl | O_NONBLOCK)
        var bs: Int32 = 256 * 1024
        _ = setsockopt(
            f, SOL_SOCKET, SO_RCVBUF, &bs,
            socklen_t(MemoryLayout<Int32>.size)
        )
    }

    deinit {
        stop()
        close(fd)
    }

    func addTarget(_ ip: IPv4, maxInflight: Int = 6) {
        lock.lock()
        targets[ip.raw] = TargetState(maxInflight: maxInflight)
        lock.unlock()
    }

    func removeTarget(_ ip: IPv4) {
        lock.lock()
        targets.removeValue(forKey: ip.raw)
        lock.unlock()
    }

    func pingOnce(_ ip: IPv4) {
        queue.async { [weak self] in
            self?.sendEcho(to: ip, seq: 0xFFFF)
        }
    }

    func start(hz: Int) {
        let ms = max(1, 1000 / hz)
        let r = DispatchSource.makeReadSource(
            fileDescriptor: fd, queue: queue
        )
        r.setEventHandler { [weak self] in self?.drainRecv() }
        r.resume()
        recvSource = r
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(
            deadline: .now(),
            repeating: .milliseconds(ms),
            leeway: .milliseconds(1)
        )
        t.setEventHandler { [weak self] in
            self?.tick()
        }
        t.resume()
        sendTimer = t
    }

    func stop() {
        sendTimer?.cancel()
        sendTimer = nil
        recvSource?.cancel()
        recvSource = nil
    }

    private func tick() {
        let now = nowNs()
        let timeoutNs: UInt64 = 1_500_000_000
        var toSend: [(IPv4, UInt16)] = []
        var timedOut: [(IPv4, UInt16, UInt64)] = []
        lock.lock()
        for (raw, var st) in targets {
            let ip = IPv4(raw)
            for (seq, sentAt) in st.inflight
            where now - sentAt > timeoutNs {
                timedOut.append((ip, seq, sentAt))
                st.inflight.removeValue(forKey: seq)
            }
            if st.inflight.count < st.maxInflight {
                var seq = st.nextSeq
                if seq == 0xFFFF {
                    seq = 0
                    st.nextSeq = 1
                } else {
                    st.nextSeq = seq &+ 1
                }
                st.inflight[seq] = now
                toSend.append((ip, seq))
            }
            targets[raw] = st
        }
        lock.unlock()
        let cb = onSample
        for (ip, seq, sentAt) in timedOut {
            cb?(ip, Sample(sendNs: sentAt, rttNs: nil, seq: seq))
        }
        for (ip, seq) in toSend {
            sendEcho(to: ip, seq: seq)
        }
    }

    private func sendEcho(to ip: IPv4, seq: UInt16) {
        let pkt = buildICMPEcho(seq: seq)
        let sz = socklen_t(MemoryLayout<sockaddr_in>.size)
        var dst = sockaddr_in()
        dst.sin_family = UInt8(AF_INET)
        dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dst.sin_port = 0
        dst.sin_addr = ip.addr
        _ = withUnsafePointer(to: &dst) { sP in
            sP.withMemoryRebound(
                to: sockaddr.self, capacity: 1
            ) { saP in
                pkt.withUnsafeBufferPointer { bp in
                    sendto(
                        fd, bp.baseAddress, bp.count, 0, saP, sz
                    )
                }
            }
        }
    }

    private func drainRecv() {
        var buf = [UInt8](repeating: 0, count: 2048)
        while true {
            var src = sockaddr_in()
            var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(
                to: &src
            ) { sP -> Int in
                sP.withMemoryRebound(
                    to: sockaddr.self, capacity: 1
                ) { saP -> Int in
                    buf.withUnsafeMutableBufferPointer {
                        bp -> Int in
                        recvfrom(
                            fd, bp.baseAddress, bp.count,
                            0, saP, &srcLen
                        )
                    }
                }
            }
            if n < 0 { break }
            if n < 8 { continue }
            var start = 0
            if (buf[0] & 0xF0) == 0x40 {
                start = Int(buf[0] & 0x0F) * 4
            }
            if n < start + 8 { continue }
            if buf[start] != 0 { continue }
            let seq = UInt16(buf[start + 6]) << 8
                | UInt16(buf[start + 7])
            let srcIP = IPv4(src.sin_addr.s_addr)
            let now = nowNs()
            lock.lock()
            var sent: UInt64? = nil
            if var st = targets[srcIP.raw] {
                sent = st.inflight.removeValue(forKey: seq)
                targets[srcIP.raw] = st
            }
            lock.unlock()
            if let s = sent {
                let smp = Sample(
                    sendNs: s, rttNs: now - s, seq: seq
                )
                onSample?(srcIP, smp)
            }
        }
    }
}

nonisolated func lookupHostname(_ ip: IPv4) -> String? {
    var sa = sockaddr_in()
    sa.sin_family = UInt8(AF_INET)
    sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    sa.sin_addr = ip.addr
    sa.sin_port = 0
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let sz = socklen_t(MemoryLayout<sockaddr_in>.size)
    let rc = withUnsafePointer(to: &sa) { sp -> Int32 in
        sp.withMemoryRebound(
            to: sockaddr.self, capacity: 1
        ) { sap in
            getnameinfo(
                sap, sz,
                &host, socklen_t(NI_MAXHOST),
                nil, 0, NI_NAMEREQD
            )
        }
    }
    if rc != 0 { return nil }
    var n = String(cString: host)
    if n.hasSuffix(".") { n.removeLast() }
    if n.hasSuffix(".local") {
        n = String(n.dropLast(6))
    }
    // If the resolver just echoed the numeric address back,
    // treat it as "no name".
    return n == ip.description ? nil : n
}

nonisolated func measureDnsMs(_ hostname: String = "apple.com") -> Double? {
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_STREAM
    var res: UnsafeMutablePointer<addrinfo>?
    let t0 = nowNs()
    let rc = getaddrinfo(hostname, nil, &hints, &res)
    let dt = nowNs() - t0
    if let r = res { freeaddrinfo(r) }
    if rc != 0 { return nil }
    return msFromNs(dt)
}

nonisolated final class NameResolver: @unchecked Sendable {
    private let queue = DispatchQueue(
        label: "wifi.names", qos: .utility,
        attributes: .concurrent
    )
    private let lock = NSLock()
    private var resolved: [UInt32: String] = [:]
    private var inflight: Set<UInt32> = []
    var onResolved: (@Sendable (IPv4, String) -> Void)?

    func resolve(_ ip: IPv4) {
        lock.lock()
        if resolved[ip.raw] != nil || inflight.contains(ip.raw) {
            lock.unlock()
            return
        }
        inflight.insert(ip.raw)
        lock.unlock()
        queue.async { [weak self] in
            let name = lookupHostname(ip)
            self?.complete(ip, name: name)
        }
    }

    private func complete(_ ip: IPv4, name: String?) {
        lock.lock()
        inflight.remove(ip.raw)
        if let n = name { resolved[ip.raw] = n }
        lock.unlock()
        if let n = name { onResolved?(ip, n) }
    }
}

nonisolated func displayMac(_ b: [UInt8]) -> String {
    // Hide placeholder addresses that iOS/sandbox returns for
    // privacy (all zeros, or LAA bit set with remainder zero).
    if b.allSatisfy({ $0 == 0 }) { return "" }
    if b[0] == 0x02, b[1..<6].allSatisfy({ $0 == 0 }) {
        return ""
    }
    return b.map { String(format: "%02x", $0) }
        .joined(separator: ":")
}

nonisolated final class RollingStats: @unchecked Sendable {
    struct Snapshot: Sendable {
        let count: Int
        let loss: Double
        let p50: Double
        let p95: Double
        let p99: Double
        let jitter: Double
        let lastRtt: Double?
    }

    private struct Entry {
        let t: UInt64
        let rtt: UInt64?
    }

    private var entries: [Entry] = []
    private let windowNs: UInt64
    private let lock = NSLock()

    init(windowMs: Int) {
        self.windowNs = UInt64(windowMs) * 1_000_000
    }

    func add(_ s: ICMPProber.Sample) {
        lock.lock()
        entries.append(Entry(t: s.sendNs, rtt: s.rttNs))
        trimLocked()
        lock.unlock()
    }

    private func trimLocked() {
        let cutoff = nowNs() &- windowNs
        var i = 0
        while i < entries.count, entries[i].t < cutoff {
            i += 1
        }
        if i > 0 { entries.removeFirst(i) }
    }

    func snapshot() -> Snapshot {
        lock.lock()
        trimLocked()
        let copy = entries
        lock.unlock()
        let n = copy.count
        if n == 0 {
            return Snapshot(
                count: 0, loss: 0, p50: 0, p95: 0,
                p99: 0, jitter: 0, lastRtt: nil
            )
        }
        let rtts = copy.compactMap(\.rtt).sorted()
        let lost = copy.filter { $0.rtt == nil }.count
        let last = copy.last?.rtt
        let loss = Double(lost) / Double(n) * 100
        func pct(_ q: Double) -> Double {
            guard !rtts.isEmpty else { return 0 }
            let top = rtts.count - 1
            let i = min(top, Int(Double(top) * q))
            return msFromNs(rtts[i])
        }
        var jit: Double = 0
        if rtts.count > 1 {
            let mean = rtts.reduce(0.0) {
                $0 + msFromNs($1)
            } / Double(rtts.count)
            let sq = rtts.reduce(0.0) { a, v in
                let d = msFromNs(v) - mean
                return a + d * d
            }
            jit = (sq / Double(rtts.count - 1))
                .squareRoot()
        }
        return Snapshot(
            count: n, loss: loss,
            p50: pct(0.5), p95: pct(0.95),
            p99: pct(0.99), jitter: jit,
            lastRtt: last.map { msFromNs($0) }
        )
    }
}

nonisolated final class ProbeStore: @unchecked Sendable {
    private let lock = NSLock()
    private var w1: [UInt32: RollingStats] = [:]
    private var w10: [UInt32: RollingStats] = [:]

    func ensure(_ ip: IPv4) {
        lock.lock()
        if w1[ip.raw] == nil {
            w1[ip.raw] = RollingStats(windowMs: 1000)
        }
        if w10[ip.raw] == nil {
            w10[ip.raw] = RollingStats(windowMs: 10_000)
        }
        lock.unlock()
    }

    func remove(_ ip: IPv4) {
        lock.lock()
        w1.removeValue(forKey: ip.raw)
        w10.removeValue(forKey: ip.raw)
        lock.unlock()
    }

    func ingest(_ ip: IPv4, _ s: ICMPProber.Sample) {
        lock.lock()
        let a = w1[ip.raw]
        let b = w10[ip.raw]
        lock.unlock()
        a?.add(s)
        b?.add(s)
    }

    func snapshots(window: Int) -> [(IPv4, RollingStats.Snapshot)] {
        lock.lock()
        let m = window == 1 ? w1 : w10
        let pairs = m.map { ($0.key, $0.value) }
        lock.unlock()
        return pairs.map { (IPv4($0.0), $0.1.snapshot()) }
    }
}

@MainActor
final class WiFiHealth: ObservableObject {
    struct PeerView: Identifiable, Hashable {
        let id: IPv4
        let label: String
        let mac: String
        let last: Double?
        let p50: Double
        let p95: Double
        let loss: Double
        let jitter: Double
        let excess: Double
        let isGateway: Bool
    }

    @Published var status: String = "Idle"
    @Published var ifaceName: String = "—"
    @Published var selfIP: String = "—"
    @Published var gatewayIP: String = "—"
    @Published var peers: [PeerView] = []
    @Published var discoveredHosts: Int = 0
    @Published var score: Int = 0
    @Published var localScore: Int = 0
    @Published var upstreamScore: Int = 0
    @Published var floorMs: Double = 0
    @Published var rxKbps: Double = 0
    @Published var txKbps: Double = 0
    @Published var rssi: Int? = nil
    @Published var noise: Int? = nil
    @Published var channel: String? = nil
    @Published var txRate: Double? = nil
    @Published var bssid: String? = nil
    @Published var ssid: String? = nil
    @Published var dnsMs: Double? = nil
    @Published var diagnosis: String = "Initializing"
    @Published var explanationLog: [(id: Date, text: String)] = []
    @Published var aiResponse: String = ""
    @Published var aiLoading: Bool = false

    private let store = ProbeStore()
    private var lastExplanation: String = ""
    private let resolver = NameResolver()
    private var prober: ICMPProber?
    private var labels: [UInt32: String] = [:]
    private var names: [UInt32: String] = [:]
    private var macs: [UInt32: String] = [:]
    private var gateway: IPv4?
    private var wifiGateway: IPv4?
    private var dnsProbe: IPv4?
    private let internetProbe: IPv4 = IPv4("1.1.1.1")!
    private var ifName: String = ""
    private var defaultIface: String = "—"
    private var targetIps: Set<UInt32> = []
    private var lastIfStats: IfaceStats?
    private var dnsTick: Int = 0
    private var refresh: Timer?
    #if os(macOS)
    private let wifi = CWWiFiClient.shared()
    #endif

    func start() {
        stop()
        status = "Discovering network path…"
        let routes = discoverDefaultRoutes()
        guard let info = routes.first else {
            status = "No default route"
            return
        }
        let wifiIface = "en0"
        let wifiRoute = routes.first { $0.interface == wifiIface }

        ifName = info.interface
        ifaceName = info.interface
        defaultIface = info.interface
        selfIP = info.selfIP.description
        gateway = info.gateway
        wifiGateway = wifiRoute?.gateway
        dnsProbe = discoverPrimaryDNS()
        gatewayIP = info.gateway.description
        do {
            let p = try ICMPProber()
            let s = store
            p.onSample = { ip, sample in
                s.ingest(ip, sample)
            }
            addFixedTarget(
                info.gateway, label: "Gateway",
                maxInflight: 6, prober: p
            )
            if let wgw = wifiRoute?.gateway, wgw.raw != info.gateway.raw {
                addFixedTarget(
                    wgw, label: "Wi-Fi GW",
                    maxInflight: 6, prober: p
                )
            }
            if let dns = dnsProbe, dns.raw != info.gateway.raw {
                addFixedTarget(dns, label: "DNS", maxInflight: 4, prober: p)
            }
            addFixedTarget(
                internetProbe, label: "Internet",
                maxInflight: 3, prober: p
            )
            p.start(hz: 30)
            prober = p
            status = "Segmented probing at 30 Hz"
        } catch {
            status = "ICMP socket failed"
            return
        }
        resolver.onResolved = { [weak self] ip, name in
            Task { @MainActor [weak self] in
                self?.applyName(ip, name)
            }
        }
        resolver.resolve(info.gateway)
        if let wgw = wifiRoute?.gateway, wgw.raw != info.gateway.raw {
            resolver.resolve(wgw)
        }
        if let dns = dnsProbe { resolver.resolve(dns) }
        resolver.resolve(internetProbe)
        refresh = Timer.scheduledTimer(
            withTimeInterval: 0.1, repeats: true
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.tickUI()
            }
        }
    }

    func stop() {
        prober?.stop()
        prober = nil
        refresh?.invalidate()
        refresh = nil
        lastIfStats = nil
        targetIps.removeAll()
    }

    private func addFixedTarget(
        _ ip: IPv4,
        label: String,
        maxInflight: Int,
        prober: ICMPProber
    ) {
        guard !targetIps.contains(ip.raw) else { return }
        targetIps.insert(ip.raw)
        labels[ip.raw] = label
        store.ensure(ip)
        prober.addTarget(ip, maxInflight: maxInflight)
    }

    private func tickUI() {
        let snaps = store.snapshots(window: 1)
        let snaps10 = store.snapshots(window: 10)
        let valid = snaps.compactMap { pair -> Double? in
            pair.1.count > 3 ? pair.1.p50 : nil
        }.filter { $0 > 0 }
        let floor = valid.min() ?? 0
        floorMs = floor
        var views: [PeerView] = []
        for (ip, snap) in snaps {
            let fallback = labels[ip.raw] ?? ip.description
            let label = names[ip.raw] ?? fallback
            views.append(PeerView(
                id: ip,
                label: label,
                mac: macs[ip.raw] ?? "",
                last: snap.lastRtt,
                p50: snap.p50,
                p95: snap.p95,
                loss: snap.loss,
                jitter: snap.jitter,
                excess: max(0, snap.p50 - floor),
                isGateway: ip.raw == gateway?.raw
            ))
        }
        views.sort {
            if $0.isGateway != $1.isGateway { return $0.isGateway }
            return $0.id.raw < $1.id.raw
        }
        peers = views
        discoveredHosts = peers.count
        updateThroughput()
        updateWiFiInfo()
        let scores = computeScores(snaps10: snaps10)
        localScore = scores.local
        upstreamScore = scores.upstream
        score = scores.overall
        diagnosis = computeDiagnosis(snaps10: snaps10)
        let expl = computeExplanation(snaps10: snaps10)
        let skeleton = expl.replacingOccurrences(
            of: "[0-9]+\\.?[0-9]*", with: "#",
            options: .regularExpression
        )
        if skeleton != lastExplanation {
            lastExplanation = skeleton
            explanationLog.insert((id: Date(), text: expl), at: 0)
            if explanationLog.count > 10 {
                explanationLog.removeLast(explanationLog.count - 10)
            }
        } else if let first = explanationLog.first {
            // Same shape, just update numbers in-place
            explanationLog[0] = (id: first.id, text: expl)
        }
        dnsTick += 1
        if dnsTick % 20 == 1 { // every ~2s (tick is 0.1s)
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let ms = measureDnsMs()
                Task { @MainActor [weak self] in
                    self?.dnsMs = ms
                }
            }
        }
    }

    private func updateThroughput() {
        guard let curr = ifaceStats(name: ifName) else { return }
        defer { lastIfStats = curr }
        guard let prev = lastIfStats,
              curr.ts > prev.ts else { return }
        let dt = Double(curr.ts - prev.ts) / 1e9
        let rx = delta32(curr.ibytes, prev.ibytes)
        let tx = delta32(curr.obytes, prev.obytes)
        let a = 0.3 // EMA smoothing factor
        rxKbps = a * (Double(rx) * 8.0 / dt / 1000.0) + (1 - a) * rxKbps
        txKbps = a * (Double(tx) * 8.0 / dt / 1000.0) + (1 - a) * txKbps
    }

    private func delta32(_ c: UInt64, _ p: UInt64) -> UInt64 {
        if c >= p { return c - p }
        return c &+ (UInt64(1) << 32) &- p
    }

    private func updateWiFiInfo() {
        #if os(macOS)
        if let iface = wifi.interface() {
            let r = iface.rssiValue()
            rssi = r == 0 ? nil : Int(r)
            let n = iface.noiseMeasurement()
            noise = n == 0 ? nil : Int(n)
            if let ch = iface.wlanChannel() {
                let band: String
                switch ch.channelBand {
                case .band2GHz: band = "2.4G"
                case .band5GHz: band = "5G"
                case .band6GHz: band = "6G"
                default:        band = ""
                }
                let width: String
                switch ch.channelWidth {
                case .width20MHz:  width = "/20"
                case .width40MHz:  width = "/40"
                case .width80MHz:  width = "/80"
                case .width160MHz: width = "/160"
                default:           width = ""
                }
                channel = "ch\(ch.channelNumber) \(band)\(width)"
            } else {
                channel = nil
            }
            let tr = iface.transmitRate()
            txRate = tr > 0 ? tr : nil
            bssid = iface.bssid()
            ssid = iface.ssid()
        } else {
            rssi = nil
            noise = nil
            channel = nil
            txRate = nil
            bssid = nil
            ssid = nil
        }
        #endif
    }

    private func computeScores(
        snaps10: [(IPv4, RollingStats.Snapshot)]
    ) -> (local: Int, upstream: Int, overall: Int) {
        let map = Dictionary(
            uniqueKeysWithValues:
                snaps10.map { ($0.0.raw, $0.1) }
        )
        guard let gw = gateway,
              let gwSnap = map[gw.raw],
              gwSnap.count > 5 else {
            return (0, 0, 0)
        }

        let localSnap: RollingStats.Snapshot = {
            if let wgw = wifiGateway, let s = map[wgw.raw], s.count > 5 {
                return s
            }
            return gwSnap
        }()
        let dnsSnap = dnsProbe.flatMap { map[$0.raw] }
        let netSnap = map[internetProbe.raw]

        let localQ = quality(localSnap, good: 8, bad: 120)
        let gwQ = quality(gwSnap, good: 5, bad: 90)
        let dnsQ = dnsSnap.map { quality($0, good: 20, bad: 1600) } ?? gwQ
        let netQ = netSnap.map { quality($0, good: 30, bad: 1500) } ?? dnsQ
        let upstreamQ = 0.35 * gwQ + 0.35 * dnsQ + 0.30 * netQ

        var pathScore = 0.35 * localQ + 0.20 * gwQ + 0.20 * dnsQ + 0.25 * netQ
        if localQ > 80 && netQ < 45 {
            // Penalize "false good link" cases:
            // local gateway good, upstream poor.
            pathScore -= 20
        }

        var rssiS = 70.0
        #if os(macOS)
        if let r = rssi {
            rssiS = clamp(100 * (Double(r) + 90.0) / 40.0)
        }
        #endif
        let s = 0.9 * pathScore + 0.1 * rssiS
        return (
            Int(clamp(localQ).rounded()),
            Int(clamp(upstreamQ).rounded()),
            Int(clamp(s).rounded())
        )
    }

    private func quality(
        _ s: RollingStats.Snapshot, good: Double, bad: Double
    ) -> Double {
        let rtt = clamp(100 * (bad - s.p50) / max(1, bad - good))
        let loss = clamp(100 * (5.0 - s.loss) / 5.0)
        let jit = clamp(100 * (40.0 - s.jitter) / 40.0)
        return 0.60 * rtt + 0.25 * loss + 0.15 * jit
    }

    private func computeDiagnosis(
        snaps10: [(IPv4, RollingStats.Snapshot)]
    ) -> String {
        let map = Dictionary(
            uniqueKeysWithValues:
                snaps10.map { ($0.0.raw, $0.1) }
        )
        guard let gw = gateway,
              let gwSnap = map[gw.raw],
              gwSnap.count > 5 else {
            return "Insufficient samples"
        }
        let localSnap = wifiGateway.flatMap { map[$0.raw] } ?? gwSnap
        let netSnap = map[internetProbe.raw]
        guard let iSnap = netSnap, iSnap.count > 5 else {
            return "Collecting upstream samples…"
        }
        if localSnap.p50 < 25 && iSnap.p50 > 150 {
            if defaultIface.hasPrefix("utun") {
                return "Local link good; upstream VPN/tunnel path degraded"
            }
            return "Local link good; upstream/WAN path degraded"
        }
        if localSnap.p50 > 40 || localSnap.loss > 2 {
            return "Local Wi-Fi/LAN path degraded"
        }
        return "Path looks stable"
    }

    private func computeExplanation(
        snaps10: [(IPv4, RollingStats.Snapshot)]
    ) -> String {
        let map = Dictionary(
            uniqueKeysWithValues:
                snaps10.map { ($0.0.raw, $0.1) }
        )
        guard let gw = gateway,
              let gwSnap = map[gw.raw],
              gwSnap.count > 5 else {
            return "Waiting for enough probe data"
                + " to analyze your connection."
        }
        let localSnap = wifiGateway.flatMap { map[$0.raw] } ?? gwSnap
        let netSnap = map[internetProbe.raw]

        var lines: [String] = []

        // Wi-Fi radio assessment
        #if os(macOS)
        if let r = rssi, let n = noise {
            let snr = r - n
            if snr < 15 {
                lines.append(
                    "SNR \(snr) dB is poor"
                    + " — high noise or weak signal;"
                    + " try moving closer to the AP"
                    + " or switching channels."
                )
            } else if r < -75 {
                lines.append(
                    "Signal is weak (\(r) dBm)"
                    + " despite OK noise — move"
                    + " closer to the access point."
                )
            }
        }
        if let tr = txRate, tr < 100 {
            lines.append(
                "PHY Tx rate \(Int(tr)) Mbps is low"
                + " — possible interference"
                + " or distance issue."
            )
        }
        #endif

        // VPN awareness
        if defaultIface.hasPrefix("utun") {
            lines.append(
                "Traffic routes through VPN"
                + " (\(defaultIface)); upstream"
                + " latency includes tunnel"
                + " overhead."
            )
        }

        // Local link
        if localSnap.p50 > 40 {
            let p50s = String(
                format: "%.0f", localSnap.p50
            )
            lines.append(
                "Local gateway latency is high"
                + " (\(p50s) ms) — possible"
                + " Wi-Fi congestion or AP"
                + " overload."
            )
        } else if localSnap.loss > 2 {
            let losss = String(
                format: "%.1f", localSnap.loss
            )
            lines.append(
                "Packet loss to local gateway"
                + " (\(losss)%) — check for"
                + " interference or AP issues."
            )
        }
        if localSnap.jitter > 15 {
            let jits = String(
                format: "%.1f", localSnap.jitter
            )
            lines.append(
                "High local jitter"
                + " (\(jits) ms) — bursty traffic"
                + " or channel contention."
            )
        }

        // Upstream
        if let iSnap = netSnap, iSnap.count > 5 {
            if iSnap.p50 > 150 && localSnap.p50 < 25 {
                let ip50 = String(
                    format: "%.0f", iSnap.p50
                )
                lines.append(
                    "Internet latency"
                    + " (\(ip50) ms) is far above"
                    + " local — bottleneck is"
                    + " upstream, not your Wi-Fi."
                )
            }
            if iSnap.loss > 3 {
                let iLoss = String(
                    format: "%.1f", iSnap.loss
                )
                lines.append(
                    "Internet packet loss is"
                    + " \(iLoss)% — upstream path"
                    + " is dropping packets."
                )
            }
        }

        // DNS
        if let d = dnsMs {
            if d > 200 {
                lines.append(
                    "DNS resolution took"
                    + " \(Int(d)) ms — slow DNS"
                    + " can make browsing feel"
                    + " sluggish."
                )
            }
        }

        if lines.isEmpty {
            return "Connection looks healthy."
                + " Local link and upstream path"
                + " are within normal range."
        }
        return lines.joined(separator: "\n")
    }

    func safeDiagnosticText() -> String {
        // SAFETY: This method must NEVER include IP addresses, SSIDs,
        // BSSIDs, MAC addresses, hostnames, or interface names.
        // Only anonymous numeric stats and generic labels.
        let snaps10 = store.snapshots(window: 10)
        let map = Dictionary(
            uniqueKeysWithValues:
                snaps10.map { ($0.0.raw, $0.1) }
        )
        let gwSnap = gateway.flatMap { map[$0.raw] }
        let localSnap = wifiGateway.flatMap { map[$0.raw] } ?? gwSnap
        let netSnap = map[internetProbe.raw]
        var s = ""
        s += "Local \(localScore)/100,"
            + " Upstream \(upstreamScore)/100,"
            + " Overall \(score)/100\n"
        s += String(format: "Floor %.2f ms", floorMs)
        if let ls = localSnap {
            s += String(
                format: ", Local p50 %.1f ms,"
                    + " loss %.1f%%, jitter %.1f ms",
                ls.p50, ls.loss, ls.jitter
            )
        }
        s += "\n"
        if let ns = netSnap {
            s += String(
                format: "Internet p50 %.1f ms,"
                    + " loss %.1f%%\n",
                ns.p50, ns.loss
            )
        }
        if let d = dnsMs {
            s += String(format: "DNS resolution %.0f ms\n", d)
        }
        #if os(macOS)
        if let r = rssi {
            s += "RSSI \(r) dBm"
            if let n = noise { s += ", Noise \(n) dBm, SNR \(r - n) dB" }
            s += "\n"
        }
        if let ch = channel { s += "Channel \(ch)" }
        if let tr = txRate { s += String(format: ", PHY Tx %.0f Mbps", tr) }
        if channel != nil || txRate != nil { s += "\n" }
        #endif
        s += String(
            format: "Throughput rx %.0f"
                + " / tx %.0f kbps\n",
            rxKbps, txKbps
        )
        let via = defaultIface.hasPrefix("utun")
            ? "VPN tunnel" : "direct"
        s += "Route via \(via)\n"
        s += "Diagnosis: \(diagnosis)"
        return s
    }

    func askAI() {
        guard !aiLoading else { return }
        let stats = safeDiagnosticText()
        let latest = explanationLog.first?.text ?? diagnosis
        let query = "Stats: \(stats) | \(latest)"
            + " —- reply plain text two sentences"
            + " max, no markdown,"
            + " single fix or suggestion"
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        guard let encoded = query.addingPercentEncoding(
            withAllowedCharacters: allowed
        ), let url = URL(string: "https://818233.xyz/\(encoded)") else {
            return
        }
        aiLoading = true
        aiResponse = ""
        let req = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: 30
        )
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, err in
            let text: String
            if let err = err {
                text = "Error: \(err.localizedDescription)"
            } else if let data = data,
                      let body = String(
                        data: data, encoding: .utf8
                      ) {
                // Strip HTML tags, ad banners, and dashed separator lines
                let stripped = body
                    .replacingOccurrences(
                        of: "<[^>]+>", with: "",
                        options: .regularExpression
                    )
                    .components(separatedBy: "\n")
                    .filter { line in
                        let t = line.trimmingCharacters(in: .whitespaces)
                        if t.allSatisfy({ $0 == "-" }),
                           t.count > 3 {
                            return false
                        }
                        if t.lowercased().contains("chatbyok") { return false }
                        let lo = t.lowercased()
                        if lo.contains("best native"),
                           lo.contains("experience") {
                            return false
                        }
                        return true
                    }
                    .joined(separator: "\n")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                text = stripped
                print("[WiFiAid AI] \(stripped)")
            } else {
                text = "No response"
            }
            Task { @MainActor [weak self] in
                self?.aiResponse = text
                self?.aiLoading = false
            }
        }.resume()
    }

    private func clamp(_ v: Double) -> Double {
        min(100, max(0, v))
    }

    private func applyName(_ ip: IPv4, _ name: String) {
        names[ip.raw] = name
    }
}

@main
struct WiFiAid: App {
    var body: some Scene {
        WindowGroup("WiFiAid") {
            ContentView()
            #if os(macOS)
                .frame(minWidth: 480, minHeight: 700)
            #endif
        }
    }
}

struct ContentView: View {

    @StateObject private var health = WiFiHealth()
    @State private var showAIConfirm = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                scoreCard
                infoCard
                peerList
                explanationPanel
            }
            .padding(16)
        }
        .onAppear { health.start() }
        .onDisappear { health.stop() }
        .alert("Ask AI", isPresented: $showAIConfirm) {
            Button("Send") { health.askAI() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This will send anonymous network stats (scores, latency, "
               + "throughput) to an external AI service. No IP addresses, "
               + "SSIDs, or other identifying information is included.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("WiFiAid")
                .font(.title2).bold()
            Text(health.status)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var scoreCard: some View {
        HStack(alignment: .top, spacing: 14) {
            scoreBlock(
                title: "Local",
                value: health.localScore,
                color: scoreColor(health.localScore)
            )
            scoreBlock(
                title: "Upstream",
                value: health.upstreamScore,
                color: scoreColor(health.upstreamScore)
            )
            Spacer()
            rssiView
        }
    }

    private func scoreBlock(
        title: String, value: Int, color: Color
    ) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("\(value)")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .foregroundStyle(color)
                    .monospacedDigit()
                Text("/100")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var rssiView: some View {
        #if os(macOS)
        if let r = health.rssi {
            VStack(alignment: .trailing, spacing: 1) {
                HStack(spacing: 6) {
                    Text("\(r) dBm")
                        .font(.headline.monospacedDigit())
                        .foregroundStyle(rssiColor(r))
                    if let n = health.noise {
                        Text("SNR \(r - n)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                if let ch = health.channel {
                    Text(ch).font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                if let s = health.ssid {
                    Text(s).font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        #else
        EmptyView()
        #endif
    }

    private func scoreColor(_ score: Int) -> Color {
        switch score {
        case 80...: return .green
        case 50...: return .yellow
        default:    return .red
        }
    }

    private func rssiColor(_ rssi: Int) -> Color {
        if rssi >= -50 { return .green }
        if rssi >= -67 { return .yellow }
        return .red
    }

    private var diagnosisColor: Color {
        let gap = health.localScore - health.upstreamScore
        if health.upstreamScore < 40 || gap > 35 {
            return .red
        }
        if health.upstreamScore < 65 || gap > 15 || health.localScore < 65 {
            return .orange
        }
        return .green
    }

    private var infoCard: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 12) {
                Text("iface \(health.ifaceName)")
                Text("self \(health.selfIP)")
                Spacer(minLength: 0)
            }
            HStack(spacing: 12) {
                Text("gw \(health.gatewayIP)")
                Text("\(health.discoveredHosts) probes")
                Spacer(minLength: 0)
            }
            HStack(spacing: 12) {
                Text(String(
                    format: "floor %.2f ms", health.floorMs
                ))
                let rx = fmtKbps(health.rxKbps)
                let tx = fmtKbps(health.txKbps)
                Text("rx \(rx) / tx \(tx)")
                Spacer(minLength: 0)
            }
            HStack(spacing: 12) {
                if let d = health.dnsMs {
                    Text(String(format: "dns %.0f ms", d))
                }
                #if os(macOS)
                if let tr = health.txRate {
                    Text(String(format: "phy %g Mbps", tr))
                }
                #endif
                Spacer(minLength: 0)
            }
            Text(health.diagnosis)
                .foregroundStyle(diagnosisColor)
                .lineLimit(1)
            Text("overall \(health.score)/100")
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .font(.caption.monospaced())
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .minimumScaleFactor(0.8)
    }

    private var peerList: some View {
        VStack(alignment: .leading, spacing: 0) {
            peerHeader
            Divider()
            ForEach(health.peers) { p in
                peerRow(p)
                Divider()
            }
        }
    }

    private var peerHeader: some View {
        HStack(spacing: 6) {
            Text("Peer")
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("p50")
                .frame(width: 52, alignment: .trailing)
            Text("excess")
                .frame(width: 54, alignment: .trailing)
            Text("p95")
                .frame(width: 48, alignment: .trailing)
            Text("loss")
                .frame(width: 44, alignment: .trailing)
        }
        .font(.caption2.bold())
        .padding(.vertical, 4)
    }

    private func peerRow(_ p: WiFiHealth.PeerView) -> some View {
        HStack(spacing: 6) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    if p.isGateway {
                        Image(systemName: "wifi.router")
                            .foregroundStyle(.blue)
                    }
                    Text(p.label).lineLimit(1)
                }
                Text(p.id.description)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if !p.mac.isEmpty {
                    Text(p.mac)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(fmtMs(p.p50))
                .frame(width: 52, alignment: .trailing)
            Text(fmtMs(p.excess))
                .foregroundStyle(excessColor(p.excess))
                .frame(width: 54, alignment: .trailing)
            Text(fmtMs(p.p95))
                .frame(width: 48, alignment: .trailing)
            Text(fmtPct(p.loss))
                .foregroundStyle(p.loss > 2 ? .red : .primary)
                .frame(width: 44, alignment: .trailing)
        }
        .font(.caption2.monospacedDigit())
        .padding(.vertical, 4)
    }

    private func excessColor(_ v: Double) -> Color {
        switch v {
        case ..<1: return .secondary
        case ..<5: return .primary
        case ..<20: return .orange
        default:   return .red
        }
    }

    private static let timeFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    private var explanationPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Log").font(.caption.bold())
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                ForEach(health.explanationLog, id: \.id) { entry in
                    HStack(alignment: .top, spacing: 6) {
                        Text(Self.timeFmt.string(from: entry.id))
                            .foregroundStyle(.tertiary)
                        Text(entry.text)
                            .textSelection(.enabled)
                    }
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
#if         ASK_AI // just for fun
            askAIButton
            if !health.aiResponse.isEmpty {
                Text(health.aiResponse)
                    .font(.caption)
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
#endif
        }
    }

    private var askAIButton: some View {
        AskAIGlowButton(loading: health.aiLoading) {
            showAIConfirm = true
        }
    }
}

private struct AskAIGlowButton: View {
    let loading: Bool
    let action: () -> Void
    @State private var stops: [Gradient.Stop] = Self.randomStops()

    private static let colors: [Color] = [
        Color(red: 0.74, green: 0.51, blue: 0.95), // #BC82F3
        Color(red: 0.96, green: 0.73, blue: 0.92), // #F5B9EA
        Color(red: 0.55, green: 0.62, blue: 1.00), // #8D9FFF
        Color(red: 1.00, green: 0.40, blue: 0.47), // #FF6778
        Color(red: 1.00, green: 0.73, blue: 0.44), // #FFBA71
        Color(red: 0.78, green: 0.53, blue: 1.00), // #C686FF
    ]

    private static func randomStops() -> [Gradient.Stop] {
        colors.map {
            Gradient.Stop(color: $0, location: Double.random(in: 0...1))
        }.sorted { $0.location < $1.location }
    }

    private let timer = Timer.publish(
        every: 0.5, on: .main, in: .common
    ).autoconnect()

    @State private var sweep: CGFloat = 0

    var body: some View {
        ZStack {
            // Outer glow layers
            glowLayer(width: 2, blur: 0)
            glowLayer(width: 4, blur: 3)
            glowLayer(width: 6, blur: 8)
            // Translucent glass interior
            Capsule()
                .fill(.ultraThinMaterial)
                .padding(1.5)
            // Aurora color wash over the glass
            Capsule()
                .fill(
                    LinearGradient(
                        stops: stops.map {
                            Gradient.Stop(
                                color: $0.color.opacity(0.15),
                                location: $0.location
                            )
                        },
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .padding(1.5)
            // Sweep highlight while loading
            if loading {
                Capsule()
                    .fill(
                        LinearGradient(
                            colors: [
                                .clear,
                                .white.opacity(0.12),
                                .clear,
                            ],
                            startPoint: UnitPoint(x: sweep - 0.3, y: 0.5),
                            endPoint: UnitPoint(x: sweep + 0.3, y: 0.5)
                        )
                    )
                    .padding(1.5)
            }
            // Label
            Text(loading ? "Asking…" : "Ask AI")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.white.opacity(0.6))
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .frame(height: 52)
        .contentShape(Capsule())
        .onTapGesture { if !loading { action() } }
        .onReceive(timer) { _ in
            withAnimation(.easeInOut(duration: 0.8)) {
                stops = Self.randomStops()
            }
        }
        .onChange(of: loading) { _, isLoading in
            if isLoading {
                sweep = -0.3
                withAnimation(
                    .linear(duration: 1.2)
                    .repeatForever(autoreverses: false)
                ) {
                    sweep = 1.3
                }
            } else {
                withAnimation(.easeOut(duration: 0.3)) {
                    sweep = 0
                }
            }
        }
    }

    private func glowLayer(width: CGFloat, blur: CGFloat) -> some View {
        Capsule()
            .strokeBorder(
                AngularGradient(
                    gradient: Gradient(stops: stops),
                    center: .center
                ),
                lineWidth: width
            )
            .blur(radius: blur)
            .opacity(0.9)
    }
}

private func fmtMs(_ v: Double) -> String {
    v < 0.01 ? "—" : String(format: "%.1f ms", v)
}

private func fmtPct(_ v: Double) -> String {
    String(format: "%.1f%%", v)
}

private func fmtKbps(_ v: Double) -> String {
    v < 1 ? "  —  " : String(format: "%5.0f kbps", v)
}

