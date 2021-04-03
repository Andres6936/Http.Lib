// Joan Andrés (@Andres6936) Github.

#include "Httplib/Server.hpp"
#include <Httplib/ThreadPool.hpp>
#include <Httplib/BufferStream.hpp>
#include <Httplib/MultipartFormDataParser.hpp>

#include <Httplib/Util/Query.hpp>
#include <Httplib/Util/Decode.hpp>
#include <Httplib/Util/Encode.hpp>
#include <Httplib/Util/Boundary.hpp>
#include <Httplib/Util/Compressor.hpp>
#include <Httplib/Util/NoCompressor.hpp>

#include <Httplib/Detail/Memory.hpp>
#include <Httplib/Detail/Header.hpp>
#include <Httplib/Detail/Content.hpp>
#include <Httplib/Detail/StatusMessage.hpp>
#include <Httplib/Detail/Socket/Common.hpp>

#include <Httplib/Enum/EncodingType.hpp>

using namespace httplib;

// HTTP server implementation
inline Server::Server()
    : new_task_queue(
    [] { return new ThreadPool(CPPHTTPLIB_THREAD_POOL_COUNT); }),
      svr_sock_(INVALID_SOCKET), is_running_(false) {
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif
}

inline Server::~Server() {}

inline Server &Server::Get(const char *pattern, Handler handler) {
  return Get(pattern, strlen(pattern), handler);
}

inline Server &Server::Get(const char *pattern, size_t pattern_len,
    Handler handler) {
  get_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Post(const char *pattern, Handler handler) {
  return Post(pattern, strlen(pattern), handler);
}

inline Server &Server::Post(const char *pattern, size_t pattern_len,
    Handler handler) {
  post_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Post(const char *pattern,
    HandlerWithContentReader handler) {
  return Post(pattern, strlen(pattern), handler);
}

inline Server &Server::Post(const char *pattern, size_t pattern_len,
    HandlerWithContentReader handler) {
  post_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Put(const char *pattern, Handler handler) {
  return Put(pattern, strlen(pattern), handler);
}

inline Server &Server::Put(const char *pattern, size_t pattern_len,
    Handler handler) {
  put_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Put(const char *pattern,
    HandlerWithContentReader handler) {
  return Put(pattern, strlen(pattern), handler);
}

inline Server &Server::Put(const char *pattern, size_t pattern_len,
    HandlerWithContentReader handler) {
  put_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Patch(const char *pattern, Handler handler) {
  return Patch(pattern, strlen(pattern), handler);
}

inline Server &Server::Patch(const char *pattern, size_t pattern_len,
    Handler handler) {
  patch_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Patch(const char *pattern,
    HandlerWithContentReader handler) {
  return Patch(pattern, strlen(pattern), handler);
}

inline Server &Server::Patch(const char *pattern, size_t pattern_len,
    HandlerWithContentReader handler) {
  patch_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Delete(const char *pattern, Handler handler) {
  return Delete(pattern, strlen(pattern), handler);
}

inline Server &Server::Delete(const char *pattern, size_t pattern_len,
    Handler handler) {
  delete_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Delete(const char *pattern,
    HandlerWithContentReader handler) {
  return Delete(pattern, strlen(pattern), handler);
}

inline Server &Server::Delete(const char *pattern, size_t pattern_len,
    HandlerWithContentReader handler) {
  delete_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline Server &Server::Options(const char *pattern, Handler handler) {
  return Options(pattern, strlen(pattern), handler);
}

inline Server &Server::Options(const char *pattern, size_t pattern_len,
    Handler handler) {
  options_handlers_.push_back(
      std::make_pair(std::regex(pattern, pattern_len), std::move(handler)));
  return *this;
}

inline bool Server::set_base_dir(const char *dir, const char *mount_point) {
  return set_mount_point(mount_point, dir);
}

inline bool Server::set_mount_point(const char *mount_point, const char *dir,
    Headers headers) {
  if (detail::is_dir(dir)) {
    std::string mnt = mount_point ? mount_point : "/";
    if (!mnt.empty() && mnt[0] == '/') {
      base_dirs_.push_back({mnt, dir, std::move(headers)});
      return true;
    }
  }
  return false;
}

inline bool Server::remove_mount_point(const char *mount_point) {
  for (auto it = base_dirs_.begin(); it != base_dirs_.end(); ++it) {
    if (it->mount_point == mount_point) {
      base_dirs_.erase(it);
      return true;
    }
  }
  return false;
}

inline Server &
Server::set_file_extension_and_mimetype_mapping(const char *ext,
    const char *mime) {
  file_extension_and_mimetype_map_[ext] = mime;

  return *this;
}

inline Server &Server::set_file_request_handler(Handler handler) {
  file_request_handler_ = std::move(handler);

  return *this;
}

inline Server &Server::set_error_handler(HandlerWithResponse handler) {
  error_handler_ = std::move(handler);
  return *this;
}

inline Server &Server::set_error_handler(Handler handler) {
  error_handler_ = [handler](const Request &req, Response &res) {
    handler(req, res);
    return HandlerResponse::Handled;
  };
  return *this;
}

inline Server &Server::set_exception_handler(ExceptionHandler handler) {
  exception_handler_ = std::move(handler);
  return *this;
}

inline Server &Server::set_pre_routing_handler(HandlerWithResponse handler) {
  pre_routing_handler_ = std::move(handler);
  return *this;
}

inline Server &Server::set_post_routing_handler(Handler handler) {
  post_routing_handler_ = std::move(handler);
  return *this;
}

inline Server &Server::set_logger(Logger logger) {
  logger_ = std::move(logger);

  return *this;
}

inline Server &
Server::set_expect_100_continue_handler(Expect100ContinueHandler handler) {
  expect_100_continue_handler_ = std::move(handler);

  return *this;
}

inline Server &Server::set_tcp_nodelay(bool on) {
  tcp_nodelay_ = on;

  return *this;
}

inline Server &Server::set_socket_options(SocketOptions socket_options) {
  socket_options_ = std::move(socket_options);

  return *this;
}

inline Server &Server::set_keep_alive_max_count(size_t count) {
  keep_alive_max_count_ = count;

  return *this;
}

inline Server &Server::set_keep_alive_timeout(time_t sec) {
  keep_alive_timeout_sec_ = sec;

  return *this;
}

inline Server &Server::set_read_timeout(time_t sec, time_t usec) {
  read_timeout_sec_ = sec;
  read_timeout_usec_ = usec;

  return *this;
}

inline Server &Server::set_write_timeout(time_t sec, time_t usec) {
  write_timeout_sec_ = sec;
  write_timeout_usec_ = usec;

  return *this;
}

inline Server &Server::set_idle_interval(time_t sec, time_t usec) {
  idle_interval_sec_ = sec;
  idle_interval_usec_ = usec;

  return *this;
}

inline Server &Server::set_payload_max_length(size_t length) {
  payload_max_length_ = length;

  return *this;
}

inline bool Server::bind_to_port(const char *host, int port, int socket_flags) {
  if (bind_internal(host, port, socket_flags) < 0) return false;
  return true;
}
inline int Server::bind_to_any_port(const char *host, int socket_flags) {
  return bind_internal(host, 0, socket_flags);
}

inline bool Server::listen_after_bind() { return listen_internal(); }

inline bool Server::listen(const char *host, int port, int socket_flags) {
  return bind_to_port(host, port, socket_flags) && listen_internal();
}

inline bool Server::is_running() const { return is_running_; }

inline void Server::stop() {
  if (is_running_) {
    assert(svr_sock_ != INVALID_SOCKET);
    std::atomic<socket_t> sock(svr_sock_.exchange(INVALID_SOCKET));
    detail::shutdown_socket(sock);
    detail::close_socket(sock);
  }
}

inline bool Server::parse_request_line(const char *s, Request &req) {
  const static std::regex re(
      "(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PRI) "
      "(([^? ]+)(?:\\?([^ ]*?))?) (HTTP/1\\.[01])\r\n");

  std::cmatch m;
  if (std::regex_match(s, m, re)) {
    req.version = std::string(m[5]);
    req.method = std::string(m[1]);
    req.target = std::string(m[2]);
    req.path = detail::decode_url(m[3], false);

    // Parse query text
    auto len = std::distance(m[4].first, m[4].second);
    if (len > 0) { detail::parse_query_text(m[4], req.params); }

    return true;
  }

  return false;
}

inline bool Server::write_response(Stream &strm, bool close_connection,
    const Request &req, Response &res) {
  return write_response_core(strm, close_connection, req, res, false);
}

inline bool Server::write_response_with_content(Stream &strm,
    bool close_connection,
    const Request &req,
    Response &res) {
  return write_response_core(strm, close_connection, req, res, true);
}

inline bool Server::write_response_core(Stream &strm, bool close_connection,
    const Request &req, Response &res,
    bool need_apply_ranges) {
  assert(res.status != -1);

  if (400 <= res.status && error_handler_ &&
      error_handler_(req, res) == HandlerResponse::Handled) {
    need_apply_ranges = true;
  }

  std::string content_type;
  std::string boundary;
  if (need_apply_ranges) { apply_ranges(req, res, content_type, boundary); }

  // Prepare additional headers
  if (close_connection || req.get_header_value("Connection") == "close") {
    res.set_header("Connection", "close");
  } else {
    std::stringstream ss;
    ss << "timeout=" << keep_alive_timeout_sec_
       << ", max=" << keep_alive_max_count_;
    res.set_header("Keep-Alive", ss.str());
  }

  if (!res.has_header("Content-Type") &&
      (!res.body.empty() || res.content_length_ > 0 || res.content_provider_)) {
    res.set_header("Content-Type", "text/plain");
  }

  if (!res.has_header("Content-Length") && res.body.empty() &&
      !res.content_length_ && !res.content_provider_) {
    res.set_header("Content-Length", "0");
  }

  if (!res.has_header("Accept-Ranges") && req.method == "HEAD") {
    res.set_header("Accept-Ranges", "bytes");
  }

  if (post_routing_handler_) { post_routing_handler_(req, res); }

  // Response line and headers
  {
    detail::BufferStream bstrm;

    if (!bstrm.write_format("HTTP/1.1 %d %s\r\n", res.status,
        detail::status_message(res.status))) {
      return false;
    }

    if (!detail::write_headers(bstrm, res.headers)) { return false; }

    // Flush buffer
    auto &data = bstrm.get_buffer();
    strm.write(data.data(), data.size());
  }

  // Body
  auto ret = true;
  if (req.method != "HEAD") {
    if (!res.body.empty()) {
      if (!strm.write(res.body)) { ret = false; }
    } else if (res.content_provider_) {
      if (!write_content_with_provider(strm, req, res, boundary,
          content_type)) {
        ret = false;
      }
    }
  }

  // Log
  if (logger_) { logger_(req, res); }

  return ret;
}


inline bool
Server::write_content_with_provider(Stream &strm, const Request &req,
    Response &res, const std::string &boundary,
    const std::string &content_type) {
  auto is_shutting_down = [this]() {
    return this->svr_sock_ == INVALID_SOCKET;
  };

  if (res.content_length_ > 0) {
    if (req.ranges.empty()) {
      return detail::write_content(strm, res.content_provider_, 0,
          res.content_length_, is_shutting_down);
    } else if (req.ranges.size() == 1) {
      auto offsets =
          detail::get_range_offset_and_length(req, res.content_length_, 0);
      auto offset = offsets.first;
      auto length = offsets.second;
      return detail::write_content(strm, res.content_provider_, offset, length,
          is_shutting_down);
    } else {
      return detail::write_multipart_ranges_data(
          strm, req, res, boundary, content_type, is_shutting_down);
    }
  } else {
    if (res.is_chunked_content_provider_) {
      auto type = detail::encoding_type(req, res);

      std::unique_ptr<detail::compressor> compressor;
      if (type == detail::EncodingType::Gzip) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
        compressor = detail::make_unique<detail::gzip_compressor>();
#endif
      } else if (type == detail::EncodingType::Brotli) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
        compressor = detail::make_unique<detail::brotli_compressor>();
#endif
      } else {
        compressor = detail::make_unique<detail::nocompressor>();
      }
      assert(compressor != nullptr);

      return detail::write_content_chunked(strm, res.content_provider_,
          is_shutting_down, *compressor);
    } else {
      return detail::write_content_without_length(strm, res.content_provider_,
          is_shutting_down);
    }
  }
}

inline bool Server::read_content(Stream &strm, Request &req, Response &res) {
  MultipartFormDataMap::iterator cur;
  if (read_content_core(
      strm, req, res,
      // Regular
      [&](const char *buf, size_t n) {
        if (req.body.size() + n > req.body.max_size()) { return false; }
        req.body.append(buf, n);
        return true;
      },
      // Multipart
      [&](const MultipartFormData &file) {
        cur = req.files.emplace(file.name, file);
        return true;
      },
      [&](const char *buf, size_t n) {
        auto &content = cur->second.content;
        if (content.size() + n > content.max_size()) { return false; }
        content.append(buf, n);
        return true;
      })) {
    const auto &content_type = req.get_header_value("Content-Type");
    if (!content_type.find("application/x-www-form-urlencoded")) {
      detail::parse_query_text(req.body, req.params);
    }
    return true;
  }
  return false;
}

inline bool Server::read_content_with_content_receiver(
    Stream &strm, Request &req, Response &res, ContentReceiver receiver,
    MultipartContentHeader multipart_header,
    ContentReceiver multipart_receiver) {
  return read_content_core(strm, req, res, std::move(receiver),
      std::move(multipart_header),
      std::move(multipart_receiver));
}

inline bool Server::read_content_core(Stream &strm, Request &req, Response &res,
    ContentReceiver receiver,
    MultipartContentHeader mulitpart_header,
    ContentReceiver multipart_receiver) {
  detail::MultipartFormDataParser multipart_form_data_parser;
  ContentReceiverWithProgress out;

  if (req.is_multipart_form_data()) {
    const auto &content_type = req.get_header_value("Content-Type");
    std::string boundary;
    if (!detail::parse_multipart_boundary(content_type, boundary)) {
      res.status = 400;
      return false;
    }

    multipart_form_data_parser.set_boundary(std::move(boundary));
    out = [&](const char *buf, size_t n, uint64_t /*off*/, uint64_t /*len*/) {
      /* For debug
      size_t pos = 0;
      while (pos < n) {
        auto read_size = std::min<size_t>(1, n - pos);
        auto ret = multipart_form_data_parser.parse(
            buf + pos, read_size, multipart_receiver, mulitpart_header);
        if (!ret) { return false; }
        pos += read_size;
      }
      return true;
      */
      return multipart_form_data_parser.parse(buf, n, multipart_receiver,
          mulitpart_header);
    };
  } else {
    out = [receiver](const char *buf, size_t n, uint64_t /*off*/,
        uint64_t /*len*/) { return receiver(buf, n); };
  }

  if (req.method == "DELETE" && !req.has_header("Content-Length")) {
    return true;
  }

  if (!detail::read_content(strm, req, payload_max_length_, res.status, nullptr,
      out, true)) {
    return false;
  }

  if (req.is_multipart_form_data()) {
    if (!multipart_form_data_parser.is_valid()) {
      res.status = 400;
      return false;
    }
  }

  return true;
}

inline bool Server::handle_file_request(const Request &req, Response &res,
    bool head) {
  for (const auto &entry : base_dirs_) {
    // Prefix match
    if (!req.path.compare(0, entry.mount_point.size(), entry.mount_point)) {
      std::string sub_path = "/" + req.path.substr(entry.mount_point.size());
      if (detail::is_valid_path(sub_path)) {
        auto path = entry.base_dir + sub_path;
        if (path.back() == '/') { path += "index.html"; }

        if (detail::is_file(path)) {
          detail::read_file(path, res.body);
          auto type =
              detail::find_content_type(path, file_extension_and_mimetype_map_);
          if (type) { res.set_header("Content-Type", type); }
          for (const auto &kv : entry.headers) {
            res.set_header(kv.first.c_str(), kv.second);
          }
          res.status = req.has_header("Range") ? 206 : 200;
          if (!head && file_request_handler_) {
            file_request_handler_(req, res);
          }
          return true;
        }
      }
    }
  }
  return false;
}

inline socket_t
Server::create_server_socket(const char *host, int port, int socket_flags,
    SocketOptions socket_options) const {
  return detail::create_socket(
      host, port, socket_flags, tcp_nodelay_, std::move(socket_options),
      [](socket_t sock, struct addrinfo &ai) -> bool {
        if (::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen))) {
          return false;
        }
        if (::listen(sock, 5)) { // Listen through 5 channels
          return false;
        }
        return true;
      });
}

inline int Server::bind_internal(const char *host, int port, int socket_flags) {
  if (!is_valid()) { return -1; }

  svr_sock_ = create_server_socket(host, port, socket_flags, socket_options_);
  if (svr_sock_ == INVALID_SOCKET) { return -1; }

  if (port == 0) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr *>(&addr),
        &addr_len) == -1) {
      return -1;
    }
    if (addr.ss_family == AF_INET) {
      return ntohs(reinterpret_cast<struct sockaddr_in *>(&addr)->sin_port);
    } else if (addr.ss_family == AF_INET6) {
      return ntohs(reinterpret_cast<struct sockaddr_in6 *>(&addr)->sin6_port);
    } else {
      return -1;
    }
  } else {
    return port;
  }
}

inline bool Server::listen_internal() {
  auto ret = true;
  is_running_ = true;

  {
    std::unique_ptr<TaskQueue> task_queue(new_task_queue());

    while (svr_sock_ != INVALID_SOCKET) {
#ifndef _WIN32
      if (idle_interval_sec_ > 0 || idle_interval_usec_ > 0) {
#endif
        auto val = detail::select_read(svr_sock_, idle_interval_sec_,
            idle_interval_usec_);
        if (val == 0) { // Timeout
          task_queue->on_idle();
          continue;
        }
#ifndef _WIN32
      }
#endif
      socket_t sock = accept(svr_sock_, nullptr, nullptr);

      if (sock == INVALID_SOCKET) {
        if (errno == EMFILE) {
          // The per-process limit of open file descriptors has been reached.
          // Try to accept new connections after a short sleep.
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
          continue;
        }
        if (svr_sock_ != INVALID_SOCKET) {
          detail::close_socket(svr_sock_);
          ret = false;
        } else {
          ; // The server socket was closed by user.
        }
        break;
      }

#if __cplusplus > 201703L
      task_queue->enqueue([=, this]() { process_and_close_socket(sock); });
#else
      task_queue->enqueue([=]() { process_and_close_socket(sock); });
#endif
    }

    task_queue->shutdown();
  }

  is_running_ = false;
  return ret;
}

inline bool Server::routing(Request &req, Response &res, Stream &strm) {
  if (pre_routing_handler_ &&
      pre_routing_handler_(req, res) == HandlerResponse::Handled) {
    return true;
  }

  // File handler
  bool is_head_request = req.method == "HEAD";
  if ((req.method == "GET" || is_head_request) &&
      handle_file_request(req, res, is_head_request)) {
    return true;
  }

  if (detail::expect_content(req)) {
    // Content reader handler
    {
      ContentReader reader(
          [&](ContentReceiver receiver) {
            return read_content_with_content_receiver(
                strm, req, res, std::move(receiver), nullptr, nullptr);
          },
          [&](MultipartContentHeader header, ContentReceiver receiver) {
            return read_content_with_content_receiver(strm, req, res, nullptr,
                std::move(header),
                std::move(receiver));
          });

      if (req.method == "POST") {
        if (dispatch_request_for_content_reader(
            req, res, std::move(reader),
            post_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "PUT") {
        if (dispatch_request_for_content_reader(
            req, res, std::move(reader),
            put_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "PATCH") {
        if (dispatch_request_for_content_reader(
            req, res, std::move(reader),
            patch_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "DELETE") {
        if (dispatch_request_for_content_reader(
            req, res, std::move(reader),
            delete_handlers_for_content_reader_)) {
          return true;
        }
      }
    }

    // Read content into `req.body`
    if (!read_content(strm, req, res)) { return false; }
  }

  // Regular handler
  if (req.method == "GET" || req.method == "HEAD") {
    return dispatch_request(req, res, get_handlers_);
  } else if (req.method == "POST") {
    return dispatch_request(req, res, post_handlers_);
  } else if (req.method == "PUT") {
    return dispatch_request(req, res, put_handlers_);
  } else if (req.method == "DELETE") {
    return dispatch_request(req, res, delete_handlers_);
  } else if (req.method == "OPTIONS") {
    return dispatch_request(req, res, options_handlers_);
  } else if (req.method == "PATCH") {
    return dispatch_request(req, res, patch_handlers_);
  }

  res.status = 400;
  return false;
}

inline bool Server::dispatch_request(Request &req, Response &res,
    const Handlers &handlers) {
  for (const auto &x : handlers) {
    const auto &pattern = x.first;
    const auto &handler = x.second;

    if (std::regex_match(req.path, req.matches, pattern)) {
      handler(req, res);
      return true;
    }
  }
  return false;
}

inline void Server::apply_ranges(const Request &req, Response &res,
    std::string &content_type,
    std::string &boundary) {
  if (req.ranges.size() > 1) {
    boundary = detail::make_multipart_data_boundary();

    auto it = res.headers.find("Content-Type");
    if (it != res.headers.end()) {
      content_type = it->second;
      res.headers.erase(it);
    }

    res.headers.emplace("Content-Type",
        "multipart/byteranges; boundary=" + boundary);
  }

  auto type = detail::encoding_type(req, res);

  if (res.body.empty()) {
    if (res.content_length_ > 0) {
      size_t length = 0;
      if (req.ranges.empty()) {
        length = res.content_length_;
      } else if (req.ranges.size() == 1) {
        auto offsets =
            detail::get_range_offset_and_length(req, res.content_length_, 0);
        auto offset = offsets.first;
        length = offsets.second;
        auto content_range = detail::make_content_range_header_field(
            offset, length, res.content_length_);
        res.set_header("Content-Range", content_range);
      } else {
        length = detail::get_multipart_ranges_data_length(req, res, boundary,
            content_type);
      }
      res.set_header("Content-Length", std::to_string(length));
    } else {
      if (res.content_provider_) {
        if (res.is_chunked_content_provider_) {
          res.set_header("Transfer-Encoding", "chunked");
          if (type == detail::EncodingType::Gzip) {
            res.set_header("Content-Encoding", "gzip");
          } else if (type == detail::EncodingType::Brotli) {
            res.set_header("Content-Encoding", "br");
          }
        }
      }
    }
  } else {
    if (req.ranges.empty()) {
      ;
    } else if (req.ranges.size() == 1) {
      auto offsets =
          detail::get_range_offset_and_length(req, res.body.size(), 0);
      auto offset = offsets.first;
      auto length = offsets.second;
      auto content_range = detail::make_content_range_header_field(
          offset, length, res.body.size());
      res.set_header("Content-Range", content_range);
      if (offset < res.body.size()) {
        res.body = res.body.substr(offset, length);
      } else {
        res.body.clear();
        res.status = 416;
      }
    } else {
      std::string data;
      if (detail::make_multipart_ranges_data(req, res, boundary, content_type,
          data)) {
        res.body.swap(data);
      } else {
        res.body.clear();
        res.status = 416;
      }
    }

    if (type != detail::EncodingType::None) {
      std::unique_ptr<detail::compressor> compressor;
      std::string content_encoding;

      if (type == detail::EncodingType::Gzip) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
        compressor = detail::make_unique<detail::gzip_compressor>();
        content_encoding = "gzip";
#endif
      } else if (type == detail::EncodingType::Brotli) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
        compressor = detail::make_unique<detail::brotli_compressor>();
        content_encoding = "br";
#endif
      }

      if (compressor) {
        std::string compressed;
        if (compressor->compress(res.body.data(), res.body.size(), true,
            [&](const char *data, size_t data_len) {
              compressed.append(data, data_len);
              return true;
            })) {
          res.body.swap(compressed);
          res.set_header("Content-Encoding", content_encoding);
        }
      }
    }

    auto length = std::to_string(res.body.size());
    res.set_header("Content-Length", length);
  }
}

inline bool Server::dispatch_request_for_content_reader(
    Request &req, Response &res, ContentReader content_reader,
    const HandlersForContentReader &handlers) {
  for (const auto &x : handlers) {
    const auto &pattern = x.first;
    const auto &handler = x.second;

    if (std::regex_match(req.path, req.matches, pattern)) {
      handler(req, res, content_reader);
      return true;
    }
  }
  return false;
}

inline bool
Server::process_request(Stream &strm, bool close_connection,
    bool &connection_closed,
    const std::function<void(Request &)> &setup_request) {
  std::array<char, 2048> buf{};

  detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

  // Connection has been closed on client
  if (!line_reader.getline()) { return false; }

  Request req;
  Response res;

  res.version = "HTTP/1.1";

#ifdef _WIN32
  // TODO: Increase FD_SETSIZE statically (libzmq), dynamically (MySQL).
#else
#ifndef CPPHTTPLIB_USE_POLL
  // Socket file descriptor exceeded FD_SETSIZE...
  if (strm.socket() >= FD_SETSIZE) {
    Headers dummy;
    detail::read_headers(strm, dummy);
    res.status = 500;
    return write_response(strm, close_connection, req, res);
  }
#endif
#endif

  // Check if the request URI doesn't exceed the limit
  if (line_reader.size() > CPPHTTPLIB_REQUEST_URI_MAX_LENGTH) {
    Headers dummy;
    detail::read_headers(strm, dummy);
    res.status = 414;
    return write_response(strm, close_connection, req, res);
  }

  // Request line and headers
  if (!parse_request_line(line_reader.ptr(), req) ||
      !detail::read_headers(strm, req.headers)) {
    res.status = 400;
    return write_response(strm, close_connection, req, res);
  }

  if (req.get_header_value("Connection") == "close") {
    connection_closed = true;
  }

  if (req.version == "HTTP/1.0" &&
      req.get_header_value("Connection") != "Keep-Alive") {
    connection_closed = true;
  }

  strm.get_remote_ip_and_port(req.remote_addr, req.remote_port);
  req.set_header("REMOTE_ADDR", req.remote_addr);
  req.set_header("REMOTE_PORT", std::to_string(req.remote_port));

  if (req.has_header("Range")) {
    const auto &range_header_value = req.get_header_value("Range");
    if (!detail::parse_range_header(range_header_value, req.ranges)) {
      res.status = 416;
      return write_response(strm, close_connection, req, res);
    }
  }

  if (setup_request) { setup_request(req); }

  if (req.get_header_value("Expect") == "100-continue") {
    auto status = 100;
    if (expect_100_continue_handler_) {
      status = expect_100_continue_handler_(req, res);
    }
    switch (status) {
    case 100:
    case 417:
      strm.write_format("HTTP/1.1 %d %s\r\n\r\n", status,
          detail::status_message(status));
      break;
    default: return write_response(strm, close_connection, req, res);
    }
  }

  // Rounting
  bool routed = false;
  try {
    routed = routing(req, res, strm);
  } catch (std::exception &e) {
    if (exception_handler_) {
      exception_handler_(req, res, e);
      routed = true;
    } else {
      res.status = 500;
      res.set_header("EXCEPTION_WHAT", e.what());
    }
  } catch (...) {
    res.status = 500;
    res.set_header("EXCEPTION_WHAT", "UNKNOWN");
  }

  if (routed) {
    if (res.status == -1) { res.status = req.ranges.empty() ? 200 : 206; }
    return write_response_with_content(strm, close_connection, req, res);
  } else {
    if (res.status == -1) { res.status = 404; }
    return write_response(strm, close_connection, req, res);
  }
}

inline bool Server::is_valid() const { return true; }

inline bool Server::process_and_close_socket(socket_t sock) {
  auto ret = detail::process_server_socket(
      sock, keep_alive_max_count_, keep_alive_timeout_sec_, read_timeout_sec_,
      read_timeout_usec_, write_timeout_sec_, write_timeout_usec_,
      [this](Stream &strm, bool close_connection, bool &connection_closed) {
        return process_request(strm, close_connection, connection_closed,
            nullptr);
      });

  detail::shutdown_socket(sock);
  detail::close_socket(sock);
  return ret;
}