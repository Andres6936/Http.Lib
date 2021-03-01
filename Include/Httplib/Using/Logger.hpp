// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_LOGGER_HPP
#define HTTPLIB_LOGGER_HPP

#include <functional>

#include <Httplib/Request.hpp>
#include <Httplib/Response.hpp>

namespace httplib {

using Logger = std::function<void(const Request &, const Response &)>;

} // namespace httplib

#endif // HTTPLIB_LOGGER_HPP
