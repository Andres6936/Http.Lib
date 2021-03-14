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

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_MAX_COUNT
#define CPPHTTPLIB_KEEPALIVE_MAX_COUNT 5
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND 300
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_SECOND
#define CPPHTTPLIB_READ_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_USECOND
#define CPPHTTPLIB_READ_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_WRITE_TIMEOUT_SECOND
#define CPPHTTPLIB_WRITE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_WRITE_TIMEOUT_USECOND
#define CPPHTTPLIB_WRITE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_SECOND
#define CPPHTTPLIB_IDLE_INTERVAL_SECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_USECOND
#ifdef _WIN32
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 10000
#else
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 0
#endif
#endif

#ifndef CPPHTTPLIB_REQUEST_URI_MAX_LENGTH
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_REDIRECT_MAX_COUNT
#define CPPHTTPLIB_REDIRECT_MAX_COUNT 20
#endif

#ifndef CPPHTTPLIB_PAYLOAD_MAX_LENGTH
#define CPPHTTPLIB_PAYLOAD_MAX_LENGTH ((std::numeric_limits<size_t>::max)())
#endif

#ifndef CPPHTTPLIB_TCP_NODELAY
#define CPPHTTPLIB_TCP_NODELAY false
#endif

#ifndef CPPHTTPLIB_RECV_BUFSIZ
#define CPPHTTPLIB_RECV_BUFSIZ size_t(4096u)
#endif

#ifndef CPPHTTPLIB_COMPRESSION_BUFSIZ
#define CPPHTTPLIB_COMPRESSION_BUFSIZ size_t(16384u)
#endif

#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT                                           \
  ((std::max)(8u, std::thread::hardware_concurrency() > 0                      \
                      ? std::thread::hardware_concurrency() - 1                \
                      : 0))
#endif

#ifndef CPPHTTPLIB_RECV_FLAGS
#define CPPHTTPLIB_RECV_FLAGS 0
#endif

#ifndef CPPHTTPLIB_SEND_FLAGS
#define CPPHTTPLIB_SEND_FLAGS 0
#endif

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

inline std::string encode_query_param(const std::string &value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (auto c : value) {
    if (std::isalnum(static_cast<uint8_t>(c)) || c == '-' || c == '_' ||
        c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' ||
        c == ')') {
      escaped << c;
    } else {
      escaped << std::uppercase;
      escaped << '%' << std::setw(2)
              << static_cast<int>(static_cast<unsigned char>(c));
      escaped << std::nouppercase;
    }
  }

  return escaped.str();
}

inline std::string encode_url(const std::string &s) {
  std::string result;

  for (size_t i = 0; s[i]; i++) {
    switch (s[i]) {
    case ' ': result += "%20"; break;
    case '+': result += "%2B"; break;
    case '\r': result += "%0D"; break;
    case '\n': result += "%0A"; break;
    case '\'': result += "%27"; break;
    case ',': result += "%2C"; break;
    // case ':': result += "%3A"; break; // ok? probably...
    case ';': result += "%3B"; break;
    default:
      auto c = static_cast<uint8_t>(s[i]);
      if (c >= 0x80) {
        result += '%';
        char hex[4];
        auto len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
        assert(len == 2);
        result.append(hex, static_cast<size_t>(len));
      } else {
        result += s[i];
      }
      break;
    }
  }

  return result;
}

inline std::string decode_url(const std::string &s,
                              bool convert_plus_to_space) {
  std::string result;

  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 1 < s.size()) {
      if (s[i + 1] == 'u') {
        int val = 0;
        if (from_hex_to_i(s, i + 2, 4, val)) {
          // 4 digits Unicode codes
          char buff[4];
          size_t len = to_utf8(val, buff);
          if (len > 0) { result.append(buff, len); }
          i += 5; // 'u0000'
        } else {
          result += s[i];
        }
      } else {
        int val = 0;
        if (from_hex_to_i(s, i + 1, 2, val)) {
          // 2 digits hex codes
          result += static_cast<char>(val);
          i += 2; // '00'
        } else {
          result += s[i];
        }
      }
    } else if (convert_plus_to_space && s[i] == '+') {
      result += ' ';
    } else {
      result += s[i];
    }
  }

  return result;
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


enum class EncodingType { None = 0, Gzip, Brotli };

inline EncodingType encoding_type(const Request &req, const Response &res) {
  auto ret =
      detail::can_compress_content_type(res.get_header_value("Content-Type"));
  if (!ret) { return EncodingType::None; }

  const auto &s = req.get_header_value("Accept-Encoding");
  (void)(s);

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
  // TODO: 'Accept-Encoding' has br, not br;q=0
  ret = s.find("br") != std::string::npos;
  if (ret) { return EncodingType::Brotli; }
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
  // TODO: 'Accept-Encoding' has gzip, not gzip;q=0
  ret = s.find("gzip") != std::string::npos;
  if (ret) { return EncodingType::Gzip; }
#endif

  return EncodingType::None;
}

class compressor {
public:
  virtual ~compressor(){};

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool compress(const char *data, size_t data_length, bool last,
                        Callback callback) = 0;
};

class decompressor {
public:
  virtual ~decompressor() {}

  virtual bool is_valid() const = 0;

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool decompress(const char *data, size_t data_length,
                          Callback callback) = 0;
};

class nocompressor : public compressor {
public:
  ~nocompressor(){};

  bool compress(const char *data, size_t data_length, bool /*last*/,
                Callback callback) override {
    if (!data_length) { return true; }
    return callback(data, data_length);
  }
};

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



inline bool write_data(Stream &strm, const char *d, size_t l) {
  size_t offset = 0;
  while (offset < l) {
    auto length = strm.write(d + offset, l - offset);
    if (length < 0) { return false; }
    offset += static_cast<size_t>(length);
  }
  return true;
}



template <typename T>
inline bool redirect(T &cli, Request &req, Response &res,
                     const std::string &path, const std::string &location,
                     Error &error) {
  Request new_req = req;
  new_req.path = path;
  new_req.redirect_count_ -= 1;

  if (res.status == 303 && (req.method != "GET" && req.method != "HEAD")) {
    new_req.method = "GET";
    new_req.body.clear();
    new_req.headers.clear();
  }

  Response new_res;

  auto ret = cli.send(new_req, new_res, error);
  if (ret) {
    req = new_req;
    res = new_res;
    res.location = location;
  }
  return ret;
}

inline std::string params_to_query_str(const Params &params) {
  std::string query;

  for (auto it = params.begin(); it != params.end(); ++it) {
    if (it != params.begin()) { query += "&"; }
    query += it->first;
    query += "=";
    query += encode_query_param(it->second);
  }
  return query;
}

inline std::string append_query_params(const char *path, const Params &params) {
  std::string path_with_query = path;
  const static std::regex re("[^?]+\\?.*");
  auto delm = std::regex_match(path, re) ? '&' : '?';
  path_with_query += delm + params_to_query_str(params);
  return path_with_query;
}

inline void parse_query_text(const std::string &s, Params &params) {
  split(s.data(), s.data() + s.size(), '&', [&](const char *b, const char *e) {
    std::string key;
    std::string val;
    split(b, e, '=', [&](const char *b2, const char *e2) {
      if (key.empty()) {
        key.assign(b2, e2);
      } else {
        val.assign(b2, e2);
      }
    });

    if (!key.empty()) {
      params.emplace(decode_url(key, true), decode_url(val, true));
    }
  });
}

inline bool parse_multipart_boundary(const std::string &content_type,
                                     std::string &boundary) {
  auto pos = content_type.find("boundary=");
  if (pos == std::string::npos) { return false; }
  boundary = content_type.substr(pos + 9);
  if (boundary.length() >= 2 && boundary.front() == '"' &&
      boundary.back() == '"') {
    boundary = boundary.substr(1, boundary.size() - 2);
  }
  return !boundary.empty();
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

inline std::string make_multipart_data_boundary() {
  static const char data[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  // std::random_device might actually be deterministic on some
  // platforms, but due to lack of support in the c++ standard library,
  // doing better requires either some ugly hacks or breaking portability.
  std::random_device seed_gen;
  // Request 128 bits of entropy for initialization
  std::seed_seq seed_sequence{seed_gen(), seed_gen(), seed_gen(), seed_gen()};
  std::mt19937 engine(seed_sequence);

  std::string result = "--cpp-httplib-multipart-data-";

  for (auto i = 0; i < 16; i++) {
    result += data[engine() % (sizeof(data) - 1)];
  }

  return result;
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



template <typename SToken, typename CToken, typename Content>
bool process_multipart_ranges_data(const Request &req, Response &res,
                                   const std::string &boundary,
                                   const std::string &content_type,
                                   SToken stoken, CToken ctoken,
                                   Content content) {
  for (size_t i = 0; i < req.ranges.size(); i++) {
    ctoken("--");
    stoken(boundary);
    ctoken("\r\n");
    if (!content_type.empty()) {
      ctoken("Content-Type: ");
      stoken(content_type);
      ctoken("\r\n");
    }

    auto offsets = get_range_offset_and_length(req, res.body.size(), i);
    auto offset = offsets.first;
    auto length = offsets.second;

    ctoken("Content-Range: ");
    stoken(make_content_range_header_field(offset, length, res.body.size()));
    ctoken("\r\n");
    ctoken("\r\n");
    if (!content(offset, length)) { return false; }
    ctoken("\r\n");
  }

  ctoken("--");
  stoken(boundary);
  ctoken("--\r\n");

  return true;
}

inline bool make_multipart_ranges_data(const Request &req, Response &res,
                                       const std::string &boundary,
                                       const std::string &content_type,
                                       std::string &data) {
  return process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data += token; },
      [&](const char *token) { data += token; },
      [&](size_t offset, size_t length) {
        if (offset < res.body.size()) {
          data += res.body.substr(offset, length);
          return true;
        }
        return false;
      });
}

inline size_t
get_multipart_ranges_data_length(const Request &req, Response &res,
                                 const std::string &boundary,
                                 const std::string &content_type) {
  size_t data_length = 0;

  process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data_length += token.size(); },
      [&](const char *token) { data_length += strlen(token); },
      [&](size_t /*offset*/, size_t length) {
        data_length += length;
        return true;
      });

  return data_length;
}

template <typename T>
inline bool write_multipart_ranges_data(Stream &strm, const Request &req,
                                        Response &res,
                                        const std::string &boundary,
                                        const std::string &content_type,
                                        const T &is_shutting_down) {
  return process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { strm.write(token); },
      [&](const char *token) { strm.write(token); },
      [&](size_t offset, size_t length) {
        return write_content(strm, res.content_provider_, offset, length,
                             is_shutting_down);
      });
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

inline bool has_crlf(const char *s) {
  auto p = s;
  while (*p) {
    if (*p == '\r' || *p == '\n') { return true; }
    p++;
  }
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

class SSLInit {
public:
  SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    SSL_load_error_strings();
    SSL_library_init();
#else
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
  }

  ~SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    ERR_free_strings();
#endif
  }

private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSLThreadLocks thread_init_;
#endif
};

// SSL socket stream implementation
inline SSLSocketStream::SSLSocketStream(socket_t sock, SSL *ssl,
                                        time_t read_timeout_sec,
                                        time_t read_timeout_usec,
                                        time_t write_timeout_sec,
                                        time_t write_timeout_usec)
    : sock_(sock), ssl_(ssl), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec),
      write_timeout_sec_(write_timeout_sec),
      write_timeout_usec_(write_timeout_usec) {
  SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
}

inline SSLSocketStream::~SSLSocketStream() {}

inline bool SSLSocketStream::is_readable() const {
  return detail::select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

inline bool SSLSocketStream::is_writable() const {
  return detail::select_write(sock_, write_timeout_sec_, write_timeout_usec_) >
         0;
}

inline ssize_t SSLSocketStream::read(char *ptr, size_t size) {
  if (SSL_pending(ssl_) > 0) {
    return SSL_read(ssl_, ptr, static_cast<int>(size));
  } else if (is_readable()) {
    auto ret = SSL_read(ssl_, ptr, static_cast<int>(size));
    if (ret < 0) {
      auto err = SSL_get_error(ssl_, ret);
      while (err == SSL_ERROR_WANT_READ) {
        if (SSL_pending(ssl_) > 0) {
          return SSL_read(ssl_, ptr, static_cast<int>(size));
        } else if (is_readable()) {
          ret = SSL_read(ssl_, ptr, static_cast<int>(size));
          if (ret >= 0) { return ret; }
          err = SSL_get_error(ssl_, ret);
        } else {
          return -1;
        }
      }
    }
    return ret;
  }
  return -1;
}

inline ssize_t SSLSocketStream::write(const char *ptr, size_t size) {
  if (is_writable()) { return SSL_write(ssl_, ptr, static_cast<int>(size)); }
  return -1;
}

inline void SSLSocketStream::get_remote_ip_and_port(std::string &ip,
                                                    int &port) const {
  detail::get_remote_ip_and_port(sock_, ip, port);
}

inline socket_t SSLSocketStream::socket() const { return sock_; }

static SSLInit sslinit_;

} // namespace detail


// SSL HTTP client implementation
inline SSLClient::SSLClient(const std::string &host)
    : SSLClient(host, 443, std::string(), std::string()) {}

inline SSLClient::SSLClient(const std::string &host, int port)
    : SSLClient(host, port, std::string(), std::string()) {}

inline SSLClient::SSLClient(const std::string &host, int port,
                            const std::string &client_cert_path,
                            const std::string &client_key_path)
    : ClientImpl(host, port, client_cert_path, client_key_path) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
                [&](const char *b, const char *e) {
                  host_components_.emplace_back(std::string(b, e));
                });
  if (!client_cert_path.empty() && !client_key_path.empty()) {
    if (SSL_CTX_use_certificate_file(ctx_, client_cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, client_key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

inline SSLClient::SSLClient(const std::string &host, int port,
                            X509 *client_cert, EVP_PKEY *client_key)
    : ClientImpl(host, port) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
                [&](const char *b, const char *e) {
                  host_components_.emplace_back(std::string(b, e));
                });
  if (client_cert != nullptr && client_key != nullptr) {
    if (SSL_CTX_use_certificate(ctx_, client_cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, client_key) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

inline SSLClient::~SSLClient() {
  if (ctx_) { SSL_CTX_free(ctx_); }
  // Make sure to shut down SSL since shutdown_ssl will resolve to the
  // base function rather than the derived function once we get to the
  // base class destructor, and won't free the SSL (causing a leak).
  SSLClient::shutdown_ssl(socket_, true);
}

inline bool SSLClient::is_valid() const { return ctx_; }

inline void SSLClient::set_ca_cert_path(const char *ca_cert_file_path,
                                        const char *ca_cert_dir_path) {
  if (ca_cert_file_path) { ca_cert_file_path_ = ca_cert_file_path; }
  if (ca_cert_dir_path) { ca_cert_dir_path_ = ca_cert_dir_path; }
}

inline void SSLClient::set_ca_cert_store(X509_STORE *ca_cert_store) {
  if (ca_cert_store) {
    if (ctx_) {
      if (SSL_CTX_get_cert_store(ctx_) != ca_cert_store) {
        // Free memory allocated for old cert and use new store `ca_cert_store`
        SSL_CTX_set_cert_store(ctx_, ca_cert_store);
      }
    } else {
      X509_STORE_free(ca_cert_store);
    }
  }
}

inline long SSLClient::get_openssl_verify_result() const {
  return verify_result_;
}

inline SSL_CTX *SSLClient::ssl_context() const { return ctx_; }

inline bool SSLClient::create_and_connect_socket(Socket &socket, Error &error) {
  return is_valid() && ClientImpl::create_and_connect_socket(socket, error);
}

// Assumes that socket_mutex_ is locked and that there are no requests in flight
inline bool SSLClient::connect_with_proxy(Socket &socket, Response &res,
                                          bool &success, Error &error) {
  success = true;
  Response res2;
  if (!detail::process_client_socket(
          socket.sock, read_timeout_sec_, read_timeout_usec_,
          write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
            Request req2;
            req2.method = "CONNECT";
            req2.path = host_and_port_;
            return process_request(strm, req2, res2, false, error);
          })) {
    // Thread-safe to close everything because we are assuming there are no
    // requests in flight
    shutdown_ssl(socket, true);
    shutdown_socket(socket);
    close_socket(socket);
    success = false;
    return false;
  }

  if (res2.status == 407) {
    if (!proxy_digest_auth_username_.empty() &&
        !proxy_digest_auth_password_.empty()) {
      std::map<std::string, std::string> auth;
      if (detail::parse_www_authenticate(res2, auth, true)) {
        Response res3;
        if (!detail::process_client_socket(
                socket.sock, read_timeout_sec_, read_timeout_usec_,
                write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
                  Request req3;
                  req3.method = "CONNECT";
                  req3.path = host_and_port_;
                  req3.headers.insert(detail::make_digest_authentication_header(
                      req3, auth, 1, detail::random_string(10),
                      proxy_digest_auth_username_, proxy_digest_auth_password_,
                      true));
                  return process_request(strm, req3, res3, false, error);
                })) {
          // Thread-safe to close everything because we are assuming there are
          // no requests in flight
          shutdown_ssl(socket, true);
          shutdown_socket(socket);
          close_socket(socket);
          success = false;
          return false;
        }
      }
    } else {
      res = res2;
      return false;
    }
  }

  return true;
}

inline bool SSLClient::load_certs() {
  bool ret = true;

  std::call_once(initialize_cert_, [&]() {
    std::lock_guard<std::mutex> guard(ctx_mutex_);
    if (!ca_cert_file_path_.empty()) {
      if (!SSL_CTX_load_verify_locations(ctx_, ca_cert_file_path_.c_str(),
                                         nullptr)) {
        ret = false;
      }
    } else if (!ca_cert_dir_path_.empty()) {
      if (!SSL_CTX_load_verify_locations(ctx_, nullptr,
                                         ca_cert_dir_path_.c_str())) {
        ret = false;
      }
    } else {
#ifdef _WIN32
      detail::load_system_certs_on_windows(SSL_CTX_get_cert_store(ctx_));
#else
      SSL_CTX_set_default_verify_paths(ctx_);
#endif
    }
  });

  return ret;
}

inline bool SSLClient::initialize_ssl(Socket &socket, Error &error) {
  auto ssl = detail::ssl_new(
      socket.sock, ctx_, ctx_mutex_,
      [&](SSL *ssl) {
        if (server_certificate_verification_) {
          if (!load_certs()) {
            error = Error::SSLLoadingCerts;
            return false;
          }
          SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
        }

        if (!detail::ssl_connect_or_accept_nonblocking(
                socket.sock, ssl, SSL_connect, connection_timeout_sec_,
                connection_timeout_usec_)) {
          error = Error::SSLConnection;
          return false;
        }

        if (server_certificate_verification_) {
          verify_result_ = SSL_get_verify_result(ssl);

          if (verify_result_ != X509_V_OK) {
            error = Error::SSLServerVerification;
            return false;
          }

          auto server_cert = SSL_get_peer_certificate(ssl);

          if (server_cert == nullptr) {
            error = Error::SSLServerVerification;
            return false;
          }

          if (!verify_host(server_cert)) {
            X509_free(server_cert);
            error = Error::SSLServerVerification;
            return false;
          }
          X509_free(server_cert);
        }

        return true;
      },
      [&](SSL *ssl) {
        SSL_set_tlsext_host_name(ssl, host_.c_str());
        return true;
      });

  if (ssl) {
    socket.ssl = ssl;
    return true;
  }

  shutdown_socket(socket);
  close_socket(socket);
  return false;
}

inline void SSLClient::shutdown_ssl(Socket &socket, bool shutdown_gracefully) {
  if (socket.sock == INVALID_SOCKET) {
    assert(socket.ssl == nullptr);
    return;
  }
  if (socket.ssl) {
    detail::ssl_delete(ctx_mutex_, socket.ssl, shutdown_gracefully);
    socket.ssl = nullptr;
  }
  assert(socket.ssl == nullptr);
}

inline bool
SSLClient::process_socket(const Socket &socket,
                          std::function<bool(Stream &strm)> callback) {
  assert(socket.ssl);
  return detail::process_client_socket_ssl(
      socket.ssl, socket.sock, read_timeout_sec_, read_timeout_usec_,
      write_timeout_sec_, write_timeout_usec_, std::move(callback));
}

inline bool SSLClient::is_ssl() const { return true; }

inline bool SSLClient::verify_host(X509 *server_cert) const {
  /* Quote from RFC2818 section 3.1 "Server Identity"

     If a subjectAltName extension of type dNSName is present, that MUST
     be used as the identity. Otherwise, the (most specific) Common Name
     field in the Subject field of the certificate MUST be used. Although
     the use of the Common Name is existing practice, it is deprecated and
     Certification Authorities are encouraged to use the dNSName instead.

     Matching is performed using the matching rules specified by
     [RFC2459].  If more than one identity of a given type is present in
     the certificate (e.g., more than one dNSName name, a match in any one
     of the set is considered acceptable.) Names may contain the wildcard
     character * which is considered to match any single domain name
     component or component fragment. E.g., *.a.com matches foo.a.com but
     not bar.foo.a.com. f*.com matches foo.com but not bar.com.

     In some cases, the URI is specified as an IP address rather than a
     hostname. In this case, the iPAddress subjectAltName must be present
     in the certificate and must exactly match the IP in the URI.

  */
  return verify_host_with_subject_alt_name(server_cert) ||
         verify_host_with_common_name(server_cert);
}

inline bool
SSLClient::verify_host_with_subject_alt_name(X509 *server_cert) const {
  auto ret = false;

  auto type = GEN_DNS;

  struct in6_addr addr6;
  struct in_addr addr;
  size_t addr_len = 0;

#ifndef __MINGW32__
  if (inet_pton(AF_INET6, host_.c_str(), &addr6)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in6_addr);
  } else if (inet_pton(AF_INET, host_.c_str(), &addr)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in_addr);
  }
#endif

  auto alt_names = static_cast<const struct stack_st_GENERAL_NAME *>(
      X509_get_ext_d2i(server_cert, NID_subject_alt_name, nullptr, nullptr));

  if (alt_names) {
    auto dsn_matched = false;
    auto ip_mached = false;

    auto count = sk_GENERAL_NAME_num(alt_names);

    for (decltype(count) i = 0; i < count && !dsn_matched; i++) {
      auto val = sk_GENERAL_NAME_value(alt_names, i);
      if (val->type == type) {
        auto name = (const char *)ASN1_STRING_get0_data(val->d.ia5);
        auto name_len = (size_t)ASN1_STRING_length(val->d.ia5);

        switch (type) {
        case GEN_DNS: dsn_matched = check_host_name(name, name_len); break;

        case GEN_IPADD:
          if (!memcmp(&addr6, name, addr_len) ||
              !memcmp(&addr, name, addr_len)) {
            ip_mached = true;
          }
          break;
        }
      }
    }

    if (dsn_matched || ip_mached) { ret = true; }
  }

  GENERAL_NAMES_free((STACK_OF(GENERAL_NAME) *)alt_names);
  return ret;
}

inline bool SSLClient::verify_host_with_common_name(X509 *server_cert) const {
  const auto subject_name = X509_get_subject_name(server_cert);

  if (subject_name != nullptr) {
    char name[BUFSIZ];
    auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
                                              name, sizeof(name));

    if (name_len != -1) {
      return check_host_name(name, static_cast<size_t>(name_len));
    }
  }

  return false;
}

inline bool SSLClient::check_host_name(const char *pattern,
                                       size_t pattern_len) const {
  if (host_.size() == pattern_len && host_ == pattern) { return true; }

  // Wildcard match
  // https://bugs.launchpad.net/ubuntu/+source/firefox-3.0/+bug/376484
  std::vector<std::string> pattern_components;
  detail::split(&pattern[0], &pattern[pattern_len], '.',
                [&](const char *b, const char *e) {
                  pattern_components.emplace_back(std::string(b, e));
                });

  if (host_components_.size() != pattern_components.size()) { return false; }

  auto itr = pattern_components.begin();
  for (const auto &h : host_components_) {
    auto &p = *itr;
    if (p != h && p != "*") {
      auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' &&
                            !p.compare(0, p.size() - 1, h));
      if (!partial_match) { return false; }
    }
    ++itr;
  }

  return true;
}
#endif

// ----------------------------------------------------------------------------

} // namespace httplib

#endif // CPPHTTPLIB_HTTPLIB_H
