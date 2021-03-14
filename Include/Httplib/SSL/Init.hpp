// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_INIT_HPP
#define HTTPLIB_INIT_HPP

namespace httplib {

namespace detail {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT


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

#endif

}

} // namespace httplib

#endif // HTTPLIB_INIT_HPP
