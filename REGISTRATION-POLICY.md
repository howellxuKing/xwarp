# Registration and password management

- Self-registration accepts a username and, when configured, a CAPTCHA. The server generates a cryptographically random 16-character login password.
- Registration responds with `username` and `initialPassword` once. The response is not cacheable. No login token is returned and plaintext passwords are not stored for later display.
- The registration page remains on a success screen showing the username and password, provides a copy action, and requires confirmation that the credentials have been saved before navigating to login.
- Registration requests supplying a password are rejected before account creation, so outdated clients cannot silently create accounts with an unknown generated password.
- Ordinary users cannot change login passwords. This is enforced by the backend, including the self-change and account-update endpoints, as well as the UI.
- System administrators and administrators retain password-management permissions subject to existing role and MFA restrictions. The administrator's local recovery command remains available.
- An administrator resetting a user's login password invalidates that user's session without changing the user's subscription or node credentials.
- Existing user passwords remain valid. Public registration disablement, CAPTCHA, quotas and expiration policies continue to apply.
