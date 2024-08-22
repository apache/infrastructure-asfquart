Changes in 0.1.7:
- Fixed the PAT handler missing asyncio library import
- auth.require can now require role account as a type


Changes in 0.1.6:
- Custom token handler can now be set for sessions obtained through bearer tokens
- Session cookies are now secured by default (SameSite=Strict, HttpOnly, Secure=True)
