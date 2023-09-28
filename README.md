# auth
Auth project implements 2 handlers: one for generating access-refresh token pair for user authentication and another for refreshing both tokens. This service uses JWT tokens as a method of authentication, and has MongoDB as a storage for refresh tokens which are securely hashed.
