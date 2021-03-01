// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_SERVER_HPP
#define HTTPLIB_SERVER_HPP

#include <regex>
#include <functional>

#include <Httplib/Stream.hpp>
#include <Httplib/Request.hpp>
#include <Httplib/Response.hpp>
#include <Httplib/ContentReader.hpp>
#include <Httplib/Using/Logger.hpp>

namespace httplib {


class Server {
public:
  using Handler = std::function<void(const Request &, Response &)>;

  using ExceptionHandler =
  std::function<void(const Request &, Response &, std::exception &e)>;

  enum class HandlerResponse {
    Handled,
    Unhandled,
  };
  using HandlerWithResponse =
  std::function<HandlerResponse(const Request &, Response &)>;

  using HandlerWithContentReader = std::function<void(
      const Request &, Response &, const ContentReader &content_reader)>;

  using Expect100ContinueHandler =
  std::function<int(const Request &, Response &)>;

  Server();

  virtual ~Server();

  virtual bool is_valid() const;

  Server &Get(const char *pattern, Handler handler);
  Server &Get(const char *pattern, size_t pattern_len, Handler handler);
  Server &Post(const char *pattern, Handler handler);
  Server &Post(const char *pattern, size_t pattern_len, Handler handler);
  Server &Post(const char *pattern, HandlerWithContentReader handler);
  Server &Post(const char *pattern, size_t pattern_len,
      HandlerWithContentReader handler);
  Server &Put(const char *pattern, Handler handler);
  Server &Put(const char *pattern, size_t pattern_len, Handler handler);
  Server &Put(const char *pattern, HandlerWithContentReader handler);
  Server &Put(const char *pattern, size_t pattern_len,
      HandlerWithContentReader handler);
  Server &Patch(const char *pattern, Handler handler);
  Server &Patch(const char *pattern, size_t pattern_len, Handler handler);
  Server &Patch(const char *pattern, HandlerWithContentReader handler);
  Server &Patch(const char *pattern, size_t pattern_len,
      HandlerWithContentReader handler);
  Server &Delete(const char *pattern, Handler handler);
  Server &Delete(const char *pattern, size_t pattern_len, Handler handler);
  Server &Delete(const char *pattern, HandlerWithContentReader handler);
  Server &Delete(const char *pattern, size_t pattern_len,
      HandlerWithContentReader handler);
  Server &Options(const char *pattern, Handler handler);
  Server &Options(const char *pattern, size_t pattern_len, Handler handler);

  bool set_base_dir(const char *dir, const char *mount_point = nullptr);
  bool set_mount_point(const char *mount_point, const char *dir,
      Headers headers = Headers());
  bool remove_mount_point(const char *mount_point);
  Server &set_file_extension_and_mimetype_mapping(const char *ext,
      const char *mime);
  Server &set_file_request_handler(Handler handler);

  Server &set_error_handler(HandlerWithResponse handler);
  Server &set_error_handler(Handler handler);
  Server &set_exception_handler(ExceptionHandler handler);
  Server &set_pre_routing_handler(HandlerWithResponse handler);
  Server &set_post_routing_handler(Handler handler);

  Server &set_expect_100_continue_handler(Expect100ContinueHandler handler);
  Server &set_logger(Logger logger);

  Server &set_tcp_nodelay(bool on);
  Server &set_socket_options(SocketOptions socket_options);

  Server &set_keep_alive_max_count(size_t count);
  Server &set_keep_alive_timeout(time_t sec);
  Server &set_read_timeout(time_t sec, time_t usec = 0);
  Server &set_write_timeout(time_t sec, time_t usec = 0);
  Server &set_idle_interval(time_t sec, time_t usec = 0);

  Server &set_payload_max_length(size_t length);

  bool bind_to_port(const char *host, int port, int socket_flags = 0);
  int bind_to_any_port(const char *host, int socket_flags = 0);
  bool listen_after_bind();

  bool listen(const char *host, int port, int socket_flags = 0);

  bool is_running() const;
  void stop();

  std::function<TaskQueue *(void)> new_task_queue;

protected:
  bool process_request(Stream &strm, bool close_connection,
      bool &connection_closed,
      const std::function<void(Request &)> &setup_request);

  std::atomic<socket_t> svr_sock_;
  size_t keep_alive_max_count_ = CPPHTTPLIB_KEEPALIVE_MAX_COUNT;
  time_t keep_alive_timeout_sec_ = CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND;
  time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;
  time_t idle_interval_sec_ = CPPHTTPLIB_IDLE_INTERVAL_SECOND;
  time_t idle_interval_usec_ = CPPHTTPLIB_IDLE_INTERVAL_USECOND;
  size_t payload_max_length_ = CPPHTTPLIB_PAYLOAD_MAX_LENGTH;

private:
  using Handlers = std::vector<std::pair<std::regex, Handler>>;
  using HandlersForContentReader =
  std::vector<std::pair<std::regex, HandlerWithContentReader>>;

  socket_t create_server_socket(const char *host, int port, int socket_flags,
      SocketOptions socket_options) const;
  int bind_internal(const char *host, int port, int socket_flags);
  bool listen_internal();

  bool routing(Request &req, Response &res, Stream &strm);
  bool handle_file_request(const Request &req, Response &res,
      bool head = false);
  bool dispatch_request(Request &req, Response &res, const Handlers &handlers);
  bool
  dispatch_request_for_content_reader(Request &req, Response &res,
      ContentReader content_reader,
      const HandlersForContentReader &handlers);

  bool parse_request_line(const char *s, Request &req);
  void apply_ranges(const Request &req, Response &res,
      std::string &content_type, std::string &boundary);
  bool write_response(Stream &strm, bool close_connection, const Request &req,
      Response &res);
  bool write_response_with_content(Stream &strm, bool close_connection,
      const Request &req, Response &res);
  bool write_response_core(Stream &strm, bool close_connection,
      const Request &req, Response &res,
      bool need_apply_ranges);
  bool write_content_with_provider(Stream &strm, const Request &req,
      Response &res, const std::string &boundary,
      const std::string &content_type);
  bool read_content(Stream &strm, Request &req, Response &res);
  bool
  read_content_with_content_receiver(Stream &strm, Request &req, Response &res,
      ContentReceiver receiver,
      MultipartContentHeader multipart_header,
      ContentReceiver multipart_receiver);
  bool read_content_core(Stream &strm, Request &req, Response &res,
      ContentReceiver receiver,
      MultipartContentHeader mulitpart_header,
      ContentReceiver multipart_receiver);

  virtual bool process_and_close_socket(socket_t sock);

  struct MountPointEntry {
    std::string mount_point;
    std::string base_dir;
    Headers headers;
  };
  std::vector<MountPointEntry> base_dirs_;

  std::atomic<bool> is_running_;
  std::map<std::string, std::string> file_extension_and_mimetype_map_;
  Handler file_request_handler_;
  Handlers get_handlers_;
  Handlers post_handlers_;
  HandlersForContentReader post_handlers_for_content_reader_;
  Handlers put_handlers_;
  HandlersForContentReader put_handlers_for_content_reader_;
  Handlers patch_handlers_;
  HandlersForContentReader patch_handlers_for_content_reader_;
  Handlers delete_handlers_;
  HandlersForContentReader delete_handlers_for_content_reader_;
  Handlers options_handlers_;
  HandlerWithResponse error_handler_;
  ExceptionHandler exception_handler_;
  HandlerWithResponse pre_routing_handler_;
  Handler post_routing_handler_;
  Logger logger_;
  Expect100ContinueHandler expect_100_continue_handler_;

  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  SocketOptions socket_options_ = default_socket_options;
};

} // namespace httplib

#endif // HTTPLIB_SERVER_HPP
