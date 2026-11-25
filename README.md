# Wisebase Mobile Auth

Standalone FastAPI service for native Flutter Google Sign-In exchange.

## Endpoints

- `GET /`
- `GET /health`
- `POST /auth/google/mobile-exchange`

## Required environment variables

```env
PORT=80
DIRECTUS_URL=http://conntinuity_directus:80
DIRECTUS_TOKEN=your_valid_directus_service_static_token
GOOGLE_MOBILE_CLIENT_ID=xxxxx.apps.googleusercontent.com
MOBILE_AUTH_DEFAULT_ROLE_ID=uuid-of-user-role
```

Flutter should call:

```txt
https://<mobile-auth-domain>/auth/google/mobile-exchange
```

with:

```json
{
  "id_token": "GOOGLE_ID_TOKEN"
}
```
