# Azure Hosting Guide for ZEB

This project is prepared for split hosting on Azure:
- Backend (`backend/`): Azure App Service (Linux, Python)
- Frontend (`frontend/`): Azure Static Web Apps

## 1. Backend App Service Setup

1. Create App Service plan and web app (Python 3.12).
2. Configure startup command in App Service:
   - `bash startup.sh`
3. Set app settings (Configuration > Application settings):
   - `DJANGO_SECRET_KEY`
   - `DJANGO_DEBUG=False`
   - `DJANGO_ALLOWED_HOSTS=.azurewebsites.net,<your-api-app>.azurewebsites.net`
   - `DJANGO_CSRF_TRUSTED_ORIGINS=https://<your-api-app>.azurewebsites.net,https://<your-static-app>.azurestaticapps.net`
   - `DJANGO_CORS_ALLOWED_ORIGINS=https://<your-static-app>.azurestaticapps.net`
   - `GOOGLE_SAFE_BROWSING_API_KEY=<your-key>`
4. Deploy backend code from `backend/`.

## 2. Frontend Static Web App Setup

1. Set frontend environment variable before build:
   - `VITE_API_BASE_URL=https://<your-api-app>.azurewebsites.net`
2. Build command:
   - `npm install && npm run build`
3. Output folder:
   - `dist`
4. Deploy frontend code from `frontend/` to Azure Static Web Apps.

## 3. Optional AZD Usage

A root `azure.yaml` is included for Azure Developer CLI workflows.
You can initialize and customize infrastructure with `azd` from repo root.

## 4. Validation Checklist

- Backend endpoint is reachable: `https://<your-api-app>.azurewebsites.net/api/check-url/`
- Frontend calls backend successfully from Static Web App domain
- No secrets in git (`.env` stays local)
- HTTPS enforced in production (`DJANGO_DEBUG=False`)
