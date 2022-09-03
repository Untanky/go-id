# Login Service

It is the goal to write an OIDC compliant login webservice with functional load-scaling.

The web service should hava a representation for users. Users are entities that can be created, disabled, enabled and deleted. They always have at least one unique identifier and a single password. The password must be stored in encrypted format with at least a salt applied.

When a user *registers*, a new user account is created.

> Normally the user account needs to be verified through a second factor.

When a user *logs in*, the unique identifier and the password are matched against the entries in the database. When the entry exists, a JWT is presented. The JWT is either a `RefreshToken` and should be kept as secure as possible or a `MfaToken`, which can be used for MFA authentication. When the entry does not exist, an error is returned. There should be a limit to how many login requests can be authored for a specific user in a specific time range.

## Tokens

When a user consumes the `MfaToken` with a valid second factor key, they receive a `RefreshToken`.\

The `RefreshToken` can be consumed for an `AccessToken`. The RefreshToken doesn't contain any identify data, besides a session identifier. The session identifier may be used to invalidate the `RefreshToken`

The `AccessToken` is a short-lived token. The `AccessToken` is encrypted using a key-pair. The authenticity of the token can be verified by downloading the public key and decrypting the token with it. The `AccessToken` can contain personal information. It also contains the session identifier. A list of recently invalidated session identifiers can be downloaded as well.

Type | Longevity |  Encrpytion
---|---|---
Access | short (30min to 24hours) | pub-priv-key
Refresh | long (24h to 12months) | symmetric
Mfa | short (up to 5 minutes) | symmetric

## REST API

Method | Path | Description
---|---|---
POST | `user/register` | Registers a new user. 
POST | `user/register/doi` | Registers a new user.  
POST | `user/login` | Logs an existing user in with the given identifier/passkey.  
POST | `user/{:id}/deactivate` | Deactive an active user.  
POST | `user/{:id}/activate` | Activates a deactivated user.
PUT | `user/{:id}` | Updates an existing user.
DELETE | `user/{:id}` | Deletes an existing user.
POST | `token/mfa` | Exchange an MFA token and an MFA key against an refresh token.
POST | `token/refresh` | Exchange a refresh token against an access token.
POST | `token/invalidate` | Invalidates any given token.
POST | `token/validate` | Validates an access token.
GET | `token/validation/key` | Retrieve the current public key for validating the access token.
GET | `token/validation/oldSessions` | Retrieve a sorted list of recently expired sessions that are no longer be available.
