// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_NAVIGATION_HPP
#define HTTPLIB_NAVIGATION_HPP

namespace httplib {

namespace detail {

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

}

} // namespace httplib

#endif // HTTPLIB_NAVIGATION_HPP
