// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_ERROR_HPP
#define HTTPLIB_ERROR_HPP

namespace httplib {

enum Error {
  Success = 0,
  Unknown,
  Connection,
  BindIPAddress,
  Read,
  Write,
  ExceedRedirectCount,
  Canceled,
  SSLConnection,
  SSLLoadingCerts,
  SSLServerVerification,
  UnsupportedMultipartBoundaryChars,
  Compression,
};

} // namespace httplib

#endif // HTTPLIB_ERROR_HPP
