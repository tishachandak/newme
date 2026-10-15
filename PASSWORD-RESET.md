# Reset your local administrator password

Keep the app running. Double-click Reset-Password.cmd and enter your saved administrator username (case-sensitive). Your browser opens a private reset link. Enter the new password twice (10–128 characters), solve the arithmetic CAPTCHA and submit. Then sign in with the new password.

No recovery code needs typing. The owner-issued link is the authorization; CAPTCHA alone cannot reset an account. The link is single-use, expires after 15 minutes, and is invalidated after five incorrect attempts. Successful reset revokes existing sessions and preserves audit data. Links are kept out of server request URLs using a fragment, which the page clears immediately. Reloading the page requires a fresh link. The arithmetic CAPTCHA is a basic demo check, not a production bot-detection service.

For hosted installations, the deployment owner must issue recovery through their private database connection; the local launcher opens localhost by default.
