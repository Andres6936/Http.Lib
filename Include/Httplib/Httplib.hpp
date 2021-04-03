//
//  httplib.h
//
//  Copyright (c) 2020 Yuji Hirose. All rights reserved.
//  MIT License
//

#ifndef CPPHTTPLIB_HTTPLIB_H
#define CPPHTTPLIB_HTTPLIB_H

/*
 * Configuration
 */


/*
 * Headers
 */



#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cctype>
#include <climits>
#include <condition_variable>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(_WIN32) && defined(OPENSSL_USE_APPLINK)
#include <openssl/applink.c>
#endif

#include <iostream>
#include <sstream>

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error Sorry, OpenSSL versions prior to 1.1.1 are not supported
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/crypto.h>
inline const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1) {
  return M_ASN1_STRING_data(asn1);
}
#endif
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif




// ----------------------------------------------------------------------------

/*
 * Implementation
 */

namespace detail {

inline bool is_hex(char c, int &v) {
  if (0x20 <= c && isdigit(c)) {
    v = c - '0';
    return true;
  } else if ('A' <= c && c <= 'F') {
    v = c - 'A' + 10;
    return true;
  } else if ('a' <= c && c <= 'f') {
    v = c - 'a' + 10;
    return true;
  }
  return false;
}

inline bool from_hex_to_i(const std::string &s, size_t i, size_t cnt,
                          int &val) {
  if (i >= s.size()) { return false; }

  val = 0;
  for (; cnt; i++, cnt--) {
    if (!s[i]) { return false; }
    int v = 0;
    if (is_hex(s[i], v)) {
      val = val * 16 + v;
    } else {
      return false;
    }
  }
  return true;
}

inline std::string from_i_to_hex(size_t n) {
  const char *charset = "0123456789abcdef";
  std::string ret;
  do {
    ret = charset[n & 15] + ret;
    n >>= 4;
  } while (n > 0);
  return ret;
}

inline size_t to_utf8(int code, char *buff) {
  if (code < 0x0080) {
    buff[0] = (code & 0x7F);
    return 1;
  } else if (code < 0x0800) {
    buff[0] = static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
    buff[1] = static_cast<char>(0x80 | (code & 0x3F));
    return 2;
  } else if (code < 0xD800) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0xE000) { // D800 - DFFF is invalid...
    return 0;
  } else if (code < 0x10000) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0x110000) {
    buff[0] = static_cast<char>(0xF0 | ((code >> 18) & 0x7));
    buff[1] = static_cast<char>(0x80 | ((code >> 12) & 0x3F));
    buff[2] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[3] = static_cast<char>(0x80 | (code & 0x3F));
    return 4;
  }

  // NOTREACHED
  return 0;
}



inline bool is_file(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

inline bool is_valid_path(const std::string &path) {
  size_t level = 0;
  size_t i = 0;

  // Skip slash
  while (i < path.size() && path[i] == '/') {
    i++;
  }

  while (i < path.size()) {
    // Read component
    auto beg = i;
    while (i < path.size() && path[i] != '/') {
      i++;
    }

    auto len = i - beg;
    assert(len > 0);

    if (!path.compare(beg, len, ".")) {
      ;
    } else if (!path.compare(beg, len, "..")) {
      if (level == 0) { return false; }
      level--;
    } else {
      level++;
    }

    // Skip slash
    while (i < path.size() && path[i] == '/') {
      i++;
    }
  }

  return true;
}




inline void read_file(const std::string &path, std::string &out) {
  std::ifstream fs(path, std::ios_base::binary);
  fs.seekg(0, std::ios_base::end);
  auto size = fs.tellg();
  fs.seekg(0);
  out.resize(static_cast<size_t>(size));
  fs.read(&out[0], static_cast<std::streamsize>(size));
}

inline std::string file_extension(const std::string &path) {
  std::smatch m;
  static auto re = std::regex("\\.([a-zA-Z0-9]+)$");
  if (std::regex_search(path, m, re)) { return m[1].str(); }
  return std::string();
}

inline bool is_space_or_tab(char c) { return c == ' ' || c == '\t'; }

inline std::pair<size_t, size_t> trim(const char *b, const char *e, size_t left,
                                      size_t right) {
  while (b + left < e && is_space_or_tab(b[left])) {
    left++;
  }
  while (right > 0 && is_space_or_tab(b[right - 1])) {
    right--;
  }
  return std::make_pair(left, right);
}

inline std::string trim_copy(const std::string &s) {
  auto r = trim(s.data(), s.data() + s.size(), 0, s.size());
  return s.substr(r.first, r.second - r.first);
}

template <class Fn> void split(const char *b, const char *e, char d, Fn fn) {
  size_t i = 0;
  size_t beg = 0;

  while (e ? (b + i < e) : (b[i] != '\0')) {
    if (b[i] == d) {
      auto r = trim(b, e, beg, i);
      if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
      beg = i + 1;
    }
    i++;
  }

  if (i) {
    auto r = trim(b, e, beg, i);
    if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
  }
}







#if !defined _WIN32 && !defined ANDROID
#define USE_IF2IP
#endif

#ifdef USE_IF2IP
inline std::string if2ip(const std::string &ifn) {
  struct ifaddrs *ifap;
  getifaddrs(&ifap);
  for (auto ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifn == ifa->ifa_name) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        auto sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN)) {
          freeifaddrs(ifap);
          return std::string(buf, INET_ADDRSTRLEN);
        }
      }
    }
  }
  freeifaddrs(ifap);
  return std::string();
}
#endif

inline void get_remote_ip_and_port(const struct sockaddr_storage &addr,
                                   socklen_t addr_len, std::string &ip,
                                   int &port) {
  if (addr.ss_family == AF_INET) {
    port = ntohs(reinterpret_cast<const struct sockaddr_in *>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    port =
        ntohs(reinterpret_cast<const struct sockaddr_in6 *>(&addr)->sin6_port);
  }

  std::array<char, NI_MAXHOST> ipstr{};
  if (!getnameinfo(reinterpret_cast<const struct sockaddr *>(&addr), addr_len,
                   ipstr.data(), static_cast<socklen_t>(ipstr.size()), nullptr,
                   0, NI_NUMERICHOST)) {
    ip = ipstr.data();
  }
}

inline void get_remote_ip_and_port(socket_t sock, std::string &ip, int &port) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  if (!getpeername(sock, reinterpret_cast<struct sockaddr *>(&addr),
                   &addr_len)) {
    get_remote_ip_and_port(addr, addr_len, ip, port);
  }
}

inline constexpr unsigned int str2tag_core(const char *s, size_t l,
                                           unsigned int h) {
  return (l == 0) ? h
                  : str2tag_core(s + 1, l - 1,
                                 (h * 33) ^ static_cast<unsigned char>(*s));
}

inline unsigned int str2tag(const std::string &s) {
  return str2tag_core(s.data(), s.size(), 0);
}

namespace udl {

inline constexpr unsigned int operator"" _(const char *s, size_t l) {
  return str2tag_core(s, l, 0);
}

} // namespace udl

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
class brotli_compressor : public compressor {
public:
  brotli_compressor() {
    state_ = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
  }

  ~brotli_compressor() { BrotliEncoderDestroyInstance(state_); }

  bool compress(const char *data, size_t data_length, bool last,
                Callback callback) override {
    std::array<uint8_t, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};

    auto operation = last ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS;
    auto available_in = data_length;
    auto next_in = reinterpret_cast<const uint8_t *>(data);

    for (;;) {
      if (last) {
        if (BrotliEncoderIsFinished(state_)) { break; }
      } else {
        if (!available_in) { break; }
      }

      auto available_out = buff.size();
      auto next_out = buff.data();

      if (!BrotliEncoderCompressStream(state_, operation, &available_in,
                                       &next_in, &available_out, &next_out,
                                       nullptr)) {
        return false;
      }

      auto output_bytes = buff.size() - available_out;
      if (output_bytes) {
        callback(reinterpret_cast<const char *>(buff.data()), output_bytes);
      }
    }

    return true;
  }

private:
  BrotliEncoderState *state_ = nullptr;
};

class brotli_decompressor : public decompressor {
public:
  brotli_decompressor() {
    decoder_s = BrotliDecoderCreateInstance(0, 0, 0);
    decoder_r = decoder_s ? BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
                          : BROTLI_DECODER_RESULT_ERROR;
  }

  ~brotli_decompressor() {
    if (decoder_s) { BrotliDecoderDestroyInstance(decoder_s); }
  }

  bool is_valid() const override { return decoder_s; }

  bool decompress(const char *data, size_t data_length,
                  Callback callback) override {
    if (decoder_r == BROTLI_DECODER_RESULT_SUCCESS ||
        decoder_r == BROTLI_DECODER_RESULT_ERROR) {
      return 0;
    }

    const uint8_t *next_in = (const uint8_t *)data;
    size_t avail_in = data_length;
    size_t total_out;

    decoder_r = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;

    std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
    while (decoder_r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      char *next_out = buff.data();
      size_t avail_out = buff.size();

      decoder_r = BrotliDecoderDecompressStream(
          decoder_s, &avail_in, &next_in, &avail_out,
          reinterpret_cast<uint8_t **>(&next_out), &total_out);

      if (decoder_r == BROTLI_DECODER_RESULT_ERROR) { return false; }

      if (!callback(buff.data(), buff.size() - avail_out)) { return false; }
    }

    return decoder_r == BROTLI_DECODER_RESULT_SUCCESS ||
           decoder_r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  }

private:
  BrotliDecoderResult decoder_r;
  BrotliDecoderState *decoder_s = nullptr;
};
#endif



inline bool is_chunked_transfer_encoding(const Headers &headers) {
  return !strcasecmp(get_header_value(headers, "Transfer-Encoding", 0, ""),
                     "chunked");
}

inline std::string to_lower(const char *beg, const char *end) {
  std::string out;
  auto it = beg;
  while (it != end) {
    out += static_cast<char>(::tolower(*it));
    it++;
  }
  return out;
}



inline std::pair<size_t, size_t>
get_range_offset_and_length(const Request &req, size_t content_length,
                            size_t index) {
  auto r = req.ranges[index];

  if (r.first == -1 && r.second == -1) {
    return std::make_pair(0, content_length);
  }

  auto slen = static_cast<ssize_t>(content_length);

  if (r.first == -1) {
    r.first = (std::max)(static_cast<ssize_t>(0), slen - r.second);
    r.second = slen - 1;
  }

  if (r.second == -1) { r.second = slen - 1; }
  return std::make_pair(r.first, static_cast<size_t>(r.second - r.first) + 1);
}








inline std::pair<size_t, size_t>
get_range_offset_and_length(const Request &req, const Response &res,
                            size_t index) {
  auto r = req.ranges[index];

  if (r.second == -1) {
    r.second = static_cast<ssize_t>(res.content_length_) - 1;
  }

  return std::make_pair(r.first, r.second - r.first + 1);
}

inline bool expect_content(const Request &req) {
  if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" ||
      req.method == "PRI" || req.method == "DELETE") {
    return true;
  }
  // TODO: check if Content-Length is set
  return false;
}



#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
template <typename CTX, typename Init, typename Update, typename Final>
inline std::string message_digest(const std::string &s, Init init,
                                  Update update, Final final,
                                  size_t digest_length) {
  using namespace std;

  std::vector<unsigned char> md(digest_length, 0);
  CTX ctx;
  init(&ctx);
  update(&ctx, s.data(), s.size());
  final(md.data(), &ctx);

  stringstream ss;
  for (auto c : md) {
    ss << setfill('0') << setw(2) << hex << (unsigned int)c;
  }
  return ss.str();
}

inline std::string MD5(const std::string &s) {
  return message_digest<MD5_CTX>(s, MD5_Init, MD5_Update, MD5_Final,
                                 MD5_DIGEST_LENGTH);
}

inline std::string SHA_256(const std::string &s) {
  return message_digest<SHA256_CTX>(s, SHA256_Init, SHA256_Update, SHA256_Final,
                                    SHA256_DIGEST_LENGTH);
}

inline std::string SHA_512(const std::string &s) {
  return message_digest<SHA512_CTX>(s, SHA512_Init, SHA512_Update, SHA512_Final,
                                    SHA512_DIGEST_LENGTH);
}
#endif

#ifdef _WIN32
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
// NOTE: This code came up with the following stackoverflow post:
// https://stackoverflow.com/questions/9507184/can-openssl-on-windows-use-the-system-certificate-store
inline bool load_system_certs_on_windows(X509_STORE *store) {
  auto hStore = CertOpenSystemStoreW((HCRYPTPROV_LEGACY)NULL, L"ROOT");

  if (!hStore) { return false; }

  PCCERT_CONTEXT pContext = NULL;
  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) !=
         nullptr) {
    auto encoded_cert =
        static_cast<const unsigned char *>(pContext->pbCertEncoded);

    auto x509 = d2i_X509(NULL, &encoded_cert, pContext->cbCertEncoded);
    if (x509) {
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  return true;
}
#endif

class WSInit {
public:
  WSInit() {
    WSADATA wsaData;
    WSAStartup(0x0002, &wsaData);
  }

  ~WSInit() { WSACleanup(); }
};

static WSInit wsinit_;
#endif



// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c/440240#answer-440240
inline std::string random_string(size_t length) {
  auto randchar = []() -> char {
    const char charset[] = "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[static_cast<size_t>(std::rand()) % max_index];
  };
  std::string str(length, 0);
  std::generate_n(str.begin(), length, randchar);
  return str;
}



} // namespace detail


/*
 * SSL Implementation
 */
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
namespace detail {


#if OPENSSL_VERSION_NUMBER < 0x10100000L
static std::shared_ptr<std::vector<std::mutex>> openSSL_locks_;

class SSLThreadLocks {
public:
  SSLThreadLocks() {
    openSSL_locks_ =
        std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());
    CRYPTO_set_locking_callback(locking_callback);
  }

  ~SSLThreadLocks() { CRYPTO_set_locking_callback(nullptr); }

private:
  static void locking_callback(int mode, int type, const char * /*file*/,
                               int /*line*/) {
    auto &lk = (*openSSL_locks_)[static_cast<size_t>(type)];
    if (mode & CRYPTO_LOCK) {
      lk.lock();
    } else {
      lk.unlock();
    }
  }
};

#endif



static SSLInit sslinit_;

} // namespace detail


#endif

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_H
