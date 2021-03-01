// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_SOCKETOPTIONS_HPP
#define HTTPLIB_SOCKETOPTIONS_HPP

#include <functional>

#include <Httplib/Using/SocketType.hpp>

namespace httplib {

using SocketOptions = std::function<void(socket_t sock)>;

} // namespace httplib

#endif // HTTPLIB_SOCKETOPTIONS_HPP
