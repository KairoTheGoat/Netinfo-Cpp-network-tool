// netinfo.cpp - quick network status tool for Linux
// Build: g++ -std=c++17 -O2 -Wall -o netinfo netinfo.cpp
// Run:   ./netinfo [--no-speed]
// Optional: `iw` installed (pacman -S iw) for SSID / signal / bitrate details.

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

static std::string trim(std::string s) {
    auto ws = [](unsigned char c) { return std::isspace(c); };
    s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), ws));
    s.erase(std::find_if_not(s.rbegin(), s.rend(), ws).base(), s.end());
    return s;
}

static std::string readFile(const fs::path& p) {
    std::ifstream f(p);
    if (!f) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    return trim(ss.str());
}

static std::string runCmd(const std::string& cmd) {
    std::string out;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return out;
    char buf[256];
    while (fgets(buf, sizeof buf, p)) out += buf;
    pclose(p);
    return out;
}

// ---------- interfaces ----------
struct Iface {
    std::string name, state, ip, mac;
    bool wireless = false;
};

static std::vector<Iface> getInterfaces() {
    std::map<std::string, std::string> ips;
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0) {
        for (auto* p = ifa; p; p = p->ifa_next) {
            if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)p->ifa_addr)->sin_addr, buf, sizeof buf);
                ips[p->ifa_name] = buf;
            }
        }
        freeifaddrs(ifa);
    }

    std::vector<Iface> v;
    for (auto& e : fs::directory_iterator("/sys/class/net")) {
        Iface i;
        i.name = e.path().filename();
        if (i.name == "lo") continue;
        i.state = readFile(e.path() / "operstate");
        i.mac = readFile(e.path() / "address");
        i.wireless = fs::exists(e.path() / "wireless");
        i.ip = ips.count(i.name) ? ips[i.name] : "-";
        v.push_back(i);
    }
    return v;
}

// ---------- routing / dns ----------
static bool defaultGateway(std::string& iface, std::string& gw) {
    std::ifstream f("/proc/net/route");
    std::string line;
    std::getline(f, line);  // header
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string ifn, dest, gate;
        ss >> ifn >> dest >> gate;
        if (dest == "00000000") {
            in_addr a;
            a.s_addr = (uint32_t)std::stoul(gate, nullptr, 16);  // already network-order in file
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, buf, sizeof buf);
            iface = ifn;
            gw = buf;
            return true;
        }
    }
    return false;
}

static std::vector<std::string> dnsServers() {
    std::vector<std::string> v;
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string k, val;
        ss >> k >> val;
        if (k == "nameserver") v.push_back(val);
    }
    return v;
}

// ---------- wifi ----------
static void printWifi(const std::string& ifname) {
    std::string out = runCmd("iw dev " + ifname + " link 2>/dev/null");
    if (out.empty()) {
        // fallback: /proc/net/wireless
        std::ifstream f("/proc/net/wireless");
        std::string line;
        while (std::getline(f, line)) {
            if (line.find(ifname + ":") != std::string::npos) {
                std::istringstream ss(line);
                std::string n, status, link, level;
                ss >> n >> status >> link >> level;
                std::cout << "  Link quality: " << link << "  Signal: " << level << " dBm\n";
                return;
            }
        }
        std::cout << "  (install `iw` for SSID / bitrate details)\n";
        return;
    }
    if (out.find("Not connected") != std::string::npos) {
        std::cout << "  Not associated with any access point\n";
        return;
    }
    std::istringstream ss(out);
    std::string line;
    while (std::getline(ss, line)) {
        line = trim(line);
        for (const char* key : {"SSID:", "freq:", "signal:", "rx bitrate:", "tx bitrate:"}) {
            if (line.rfind(key, 0) == 0) std::cout << "  " << line << "\n";
        }
    }
}

// ---------- latency ----------
static bool makeAddr(const std::string& host, int port, sockaddr_in& out, double* dnsMs = nullptr) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    auto t0 = Clock::now();
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) return false;
    if (dnsMs) *dnsMs = msSince(t0);
    out = *(sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);
    return true;
}

// TCP connect time; ECONNREFUSED still counts (host answered)
static double tcpRtt(const sockaddr_in& addr, int timeoutMs) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    auto t0 = Clock::now();
    double ms = -1;
    int r = connect(fd, (const sockaddr*)&addr, sizeof addr);
    if (r == 0) {
        ms = msSince(t0);
    } else if (errno == EINPROGRESS) {
        pollfd p{fd, POLLOUT, 0};
        if (poll(&p, 1, timeoutMs) > 0) {
            int err = 0;
            socklen_t l = sizeof err;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
            if (err == 0 || err == ECONNREFUSED) ms = msSince(t0);
        }
    }
    close(fd);
    return ms;
}

static void latencyTest(const std::string& label, const std::string& host, int port, int samples = 5) {
    sockaddr_in addr;
    if (!makeAddr(host, port, addr)) {
        std::cout << "  " << std::left << std::setw(18) << label << "resolve failed\n";
        return;
    }
    std::vector<double> v;
    int lost = 0;
    for (int i = 0; i < samples; i++) {
        double r = tcpRtt(addr, 1500);
        if (r < 0) lost++;
        else v.push_back(r);
        usleep(100000);
    }
    std::cout << "  " << std::left << std::setw(18) << label;
    if (v.empty()) {
        std::cout << "unreachable (" << lost << "/" << samples << " lost)\n";
        return;
    }
    double mn = *std::min_element(v.begin(), v.end());
    double mx = *std::max_element(v.begin(), v.end());
    double avg = 0;
    for (double x : v) avg += x;
    avg /= v.size();
    double jit = 0;
    for (size_t i = 1; i < v.size(); i++) jit += std::fabs(v[i] - v[i - 1]);
    if (v.size() > 1) jit /= (v.size() - 1);
    std::cout << std::fixed << std::setprecision(1) << "min " << mn << " / avg " << avg << " / max " << mx
              << " ms  jitter " << jit << " ms  loss " << lost << "/" << samples << "\n";
}

// ---------- download speed (plain HTTP, no TLS) ----------
static void downloadTest(const std::string& host, const std::string& path, double maxSeconds) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), "80", &hints, &res) != 0 || !res) {
        std::cout << "  resolve failed for " << host << "\n";
        return;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    timeval tv{4, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        std::cout << "  connect failed\n";
        close(fd);
        freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);

    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: netinfo\r\n\r\n";
    send(fd, req.c_str(), req.size(), 0);

    std::vector<char> buf(64 * 1024);
    size_t total = 0;
    bool first = true;
    Clock::time_point t0;
    while (true) {
        ssize_t n = recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) break;
        if (first) {
            std::string head(buf.data(), std::min<ssize_t>(n, 12));
            if (head.find(" 200") == std::string::npos) {
                std::cout << "  server replied: " << head << " (not 200)\n";
                close(fd);
                return;
            }
            t0 = Clock::now();  // start timing at first byte (excludes connect + TTFB)
            first = false;
            continue;
        }
        total += n;
        if (msSince(t0) / 1000.0 >= maxSeconds) break;
    }
    close(fd);
    if (first || total == 0) {
        std::cout << "  no data received\n";
        return;
    }
    double secs = msSince(t0) / 1000.0;
    double mbps = (total * 8.0) / secs / 1e6;
    std::cout << std::fixed << std::setprecision(2) << "  Download: " << mbps << " Mbit/s  (" << mbps / 8.0
              << " MB/s, " << total / 1e6 << " MB in " << secs << " s)\n";
}

int main(int argc, char** argv) {
    bool speed = !(argc > 1 && std::string(argv[1]) == "--no-speed");

    std::cout << "=== Interfaces ===\n";
    auto ifs = getInterfaces();
    for (auto& i : ifs) {
        std::cout << "  " << std::left << std::setw(12) << i.name << std::setw(10) << i.state << std::setw(16) << i.ip
                  << i.mac << (i.wireless ? "  [wifi]" : "") << "\n";
    }

    std::string gwIf, gw;
    bool hasGw = defaultGateway(gwIf, gw);
    std::cout << "\n=== Route ===\n";
    if (!hasGw) {
        std::cout << "  No default route -> not connected to a network.\n";
        return 1;
    }
    std::cout << "  Default gateway: " << gw << " via " << gwIf << "\n";
    std::cout << "  DNS: ";
    for (auto& d : dnsServers()) std::cout << d << " ";
    std::cout << "\n";

    for (auto& i : ifs) {
        if (i.name == gwIf && i.wireless) {
            std::cout << "\n=== Wi-Fi (" << i.name << ") ===\n";
            printWifi(i.name);
        } else if (i.name == gwIf) {
            std::string spd = readFile("/sys/class/net/" + i.name + "/speed");
            std::cout << "\n=== Wired (" << i.name << ") ===\n  Link speed: " << (spd.empty() ? "?" : spd) << " Mbit/s\n";
        }
    }

    std::cout << "\n=== DNS ===\n";
    {
        sockaddr_in a;
        double dnsMs = 0;
        if (makeAddr("example.com", 80, a, &dnsMs))
            std::cout << std::fixed << std::setprecision(1) << "  Lookup example.com: " << dnsMs << " ms\n";
        else
            std::cout << "  DNS lookup FAILED\n";
    }

    std::cout << "\n=== Latency (TCP connect) ===\n";
    latencyTest("gateway:80", gw, 80);
    latencyTest("1.1.1.1:443", "1.1.1.1", 443);
    latencyTest("8.8.8.8:443", "8.8.8.8", 443);

    if (speed) {
        std::cout << "\n=== Speed (HTTP, ~5s max) ===\n";
        downloadTest("speedtest.tele2.net", "/100MB.zip", 5.0);
    }
    return 0;
}
