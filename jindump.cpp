#include <pcap.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <memory>

struct ap_info {
    std::string bssid;
    std::string ssid;
    int channel;
    std::string enc;     
    unsigned int beacons;
    int pwr;            
    std::string cipher;
    std::string auth;    
    time_t last_time;
    int data;
    int data_rate;
    bool updated;
    
    ap_info() : channel(0), beacons(0), pwr(0), last_time(0), data(0), data_rate(0), updated(false) {}
};

class packet_parser {
public:
    virtual void parse(const uint8_t* pkt, int len) = 0;
    virtual void show() const = 0;
    virtual ~packet_parser() = default;
};

class IE {
protected:
    uint8_t tag;
    uint8_t length;
    const uint8_t* data;

public:
    IE(uint8_t _tag, uint8_t _len, const uint8_t* _data)
        : tag(_tag), length(_len), data(_data) {}
    
    virtual void parse(ap_info& ap) = 0;
    virtual ~IE() = default;

    static std::unique_ptr<IE> create(uint8_t tag, uint8_t len, const uint8_t* data);
};

class TaggedParameter : public IE {
protected:
    uint8_t element_id;
    uint8_t element_length;

public:
    TaggedParameter(uint8_t tag, uint8_t len, const uint8_t* data)
        : IE(tag, len, data) {
        element_id = tag;
        element_length = len;
    }
};

class SSID_IE : public TaggedParameter {
public:
    SSID_IE(uint8_t tag, uint8_t len, const uint8_t* data)
        : TaggedParameter(tag, len, data) {}
    
    void parse(ap_info& ap) override {
        if (length > 0) {
            ap.ssid.assign(reinterpret_cast<const char*>(data), length);
        }
    }
};

class DS_Parameter_IE : public TaggedParameter {
public:
    DS_Parameter_IE(uint8_t tag, uint8_t len, const uint8_t* data)
        : TaggedParameter(tag, len, data) {}
    
    void parse(ap_info& ap) override {
        if (length > 0) {
            ap.channel = data[0];
        }
    }
};

class Supported_Rates_IE : public TaggedParameter {
public:
    Supported_Rates_IE(uint8_t tag, uint8_t len, const uint8_t* data)
        : TaggedParameter(tag, len, data) {}
    
    void parse(ap_info& ap) override {
        if (length > 0) {
            for (size_t i = 0; i < length; i++) {
                int rate = (data[i] & 0x7F) * 500;  // kbps
                ap.data_rate = std::max(ap.data_rate, rate);
            }
        }
    }
};

class Extended_Supported_Rates_IE : public Supported_Rates_IE {
public:
    Extended_Supported_Rates_IE(uint8_t tag, uint8_t len, const uint8_t* data)
        : Supported_Rates_IE(tag, len, data) {}
};

class RSN_IE : public TaggedParameter {
public:
    RSN_IE(uint8_t tag, uint8_t len, const uint8_t* data)
        : TaggedParameter(tag, len, data) {}
    
    void parse(ap_info& ap) override {
        if (length < 2) return;

        ap.enc = "WPA2";
        
        const uint8_t* ptr = data + 2;
        
        if (ptr + 4 > data + length) return;
        ptr += 4;
        
        if (ptr + 2 > data + length) return;
        uint16_t pair_count = *(uint16_t*)ptr;
        ptr += 2;
        
        if (ptr + 4 * pair_count > data + length) return;
        for (int i = 0; i < pair_count; i++) {
            if (memcmp(ptr, "\x00\x0F\xAC", 3) == 0) {
                switch(ptr[3]) {
                    case 4: ap.cipher = "CCMP"; break;
                    case 2: ap.cipher = "TKIP"; break;
                }
            }
            ptr += 4;
        }
        
        if (ptr + 2 > data + length) return;
        uint16_t akm_count = *(uint16_t*)ptr;
        ptr += 2;
        
        if (ptr + 4 * akm_count > data + length) return;
        for (int i = 0; i < akm_count; i++) {
            if (memcmp(ptr, "\x00\x0F\xAC", 3) == 0) {
                switch(ptr[3]) {
                    case 2: ap.auth = "PSK"; break;
                    case 1: ap.auth = "MGT"; break;
                }
            }
            ptr += 4;
        }
    }
};

std::unique_ptr<IE> IE::create(uint8_t tag, uint8_t len, const uint8_t* data) {
    switch(tag) {
        case 0:  // SSID
            return std::unique_ptr<IE>(new SSID_IE(tag, len, data));
        case 1:  // Supported Rates
            return std::unique_ptr<IE>(new Supported_Rates_IE(tag, len, data));
        case 3:  // DS Parameter Set (Channel)
            return std::unique_ptr<IE>(new DS_Parameter_IE(tag, len, data));
        case 48: // RSN
            return std::unique_ptr<IE>(new RSN_IE(tag, len, data));
        case 50: // Extended Supported Rates
            return std::unique_ptr<IE>(new Extended_Supported_Rates_IE(tag, len, data));
        default:
            return nullptr;
    }
}


class dot11_parser : public packet_parser {
private:
    std::map<std::string, ap_info> aps;
    time_t start_time;
    mutable bool need_header;

public:
    dot11_parser() : start_time(time(nullptr)), need_header(true) {}

    void parse(const uint8_t* pkt, int len) override {
        uint16_t rtap_len = *(uint16_t*)(pkt + 2);  
        const uint8_t* frame = pkt + rtap_len;

        uint16_t fc = *(uint16_t*)frame;  
        if ((fc & 0x00FC) != 0x0080) {
            return;
        }

        ap_info ap;
        ap.last_time = time(nullptr);
        
        char bssid[18];
        const uint8_t* bssid_ptr = frame + 16;
        std::snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                bssid_ptr[0], bssid_ptr[1], bssid_ptr[2],
                bssid_ptr[3], bssid_ptr[4], bssid_ptr[5]);
        ap.bssid = bssid;

        ap.pwr = -(int8_t)pkt[22];

        parse_ies(frame + 36, pkt + len, ap);

        auto& stored = aps[ap.bssid];
        bool is_new = stored.bssid.empty();
        bool is_updated = false;

        if (is_new) {
            stored = ap;
            is_updated = true;
        } else {
            // 값이 변경되었는지 확인
            if (stored.beacons != ap.beacons) is_updated = true;
            if (ap.pwr != 0 && stored.pwr != ap.pwr) is_updated = true;
            if (ap.data_rate > stored.data_rate) is_updated = true;
            if (stored.ssid != ap.ssid && !ap.ssid.empty()) is_updated = true;
            if (stored.channel != ap.channel && ap.channel != 0) is_updated = true;
            if (stored.enc != ap.enc && !ap.enc.empty()) is_updated = true;
            if (stored.cipher != ap.cipher && !ap.cipher.empty()) is_updated = true;
            if (stored.auth != ap.auth && !ap.auth.empty()) is_updated = true;

            // 값 업데이트
            stored.beacons++;
            stored.last_time = ap.last_time;
            if (ap.pwr != 0) stored.pwr = ap.pwr;
            if (ap.data_rate > stored.data_rate) stored.data_rate = ap.data_rate;
            if (!ap.ssid.empty()) stored.ssid = ap.ssid;
            if (ap.channel != 0) stored.channel = ap.channel;
            if (!ap.enc.empty()) stored.enc = ap.enc;
            if (!ap.cipher.empty()) stored.cipher = ap.cipher;
            if (!ap.auth.empty()) stored.auth = ap.auth;
        }

        stored.updated = is_updated;
        if (is_updated) {
            need_header = true;  // 업데이트가 있으면 헤더를 다시 출력
        }
    }

    void show() const override {
        if (!need_header) {
            return;  // 업데이트된 내용이 없으면 출력하지 않음
        }

        // 화면 지우기
        std::cout << "\033[2J\033[H";

        // 헤더 출력
        std::cout << "\n CH " << std::setw(2) << "1" << " ][ Started: " 
                  << get_time() << " ]\n\n";

        std::cout << " BSSID              PWR  Beacons    #Data  CH  MB   ENC     CIPHER  AUTH ESSID\n";
        std::cout << std::string(80, '-') << std::endl;

        // 모든 AP 정보 출력
        for (const auto& p : aps) {
            const auto& ap = p.second;
            std::cout << " " 
                      << std::left << std::setw(17) << ap.bssid
                      << std::right << std::setw(4) << "-" << std::abs(ap.pwr)
                      << std::setw(10) << ap.beacons
                      << std::setw(8) << ap.data 
                      << std::setw(4) << ap.channel
                      << std::setw(5) << ap.data_rate/1000
                      << " " << std::left << std::setw(8) << ap.enc
                      << std::setw(8) << ap.cipher
                      << std::setw(5) << ap.auth
                      << " " << ap.ssid
                      << std::endl;

            const_cast<ap_info&>(ap).updated = false;
        }

        need_header = false;  // 출력 완료 후 플래그 리셋
    }


private:
    void print_header() const {
        std::cout << "\n CH " << std::setw(2) << "1" << " ][ Started: " 
                  << get_time() << " ]\n\n";

        std::cout << " BSSID              PWR  Beacons    #Data  CH  MB   ENC     CIPHER  AUTH ESSID\n";
        std::cout << std::string(80, '-') << std::endl;
    }

    std::string get_time() const {
        time_t now = time(nullptr);
        struct tm* ti = localtime(&now);
        char buf[9];
        strftime(buf, sizeof(buf), "%H:%M:%S", ti);
        return std::string(buf);
    }

    void parse_ies(const uint8_t* start, const uint8_t* end, ap_info& ap) {
        const uint8_t* ptr = start;
        
        while (ptr + 2 <= end) {
            uint8_t id = ptr[0];
            uint8_t len = ptr[1];
            const uint8_t* data = ptr + 2;
            
            if (ptr + 2 + len > end) break;

            auto ie = IE::create(id, len, data);
            if (ie) {
                ie->parse(ap);
            }
            
            ptr += 2 + len;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        std::cerr << "Example: " << argv[0] << " wlan0\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Could not open device " << argv[1] << ": " << errbuf << std::endl;
        return 1;
    }

    dot11_parser parser;
    struct pcap_pkthdr header;
    const u_char* packet;

    while (true) {
        packet = pcap_next(handle, &header);
        if (packet) {
            parser.parse(packet, header.len);
            parser.show();
        }
    }

    pcap_close(handle);
    return 0;
}

