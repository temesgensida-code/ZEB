# Azure Deployment Plan

Status: Ready for Validation
Date: 2026-04-17
Project: ZEB (Django backend + React frontend)

## 1. Project Analysis
- Mode: MODIFY existing project
- Backend: Django REST API in `backend/`
- Frontend: React + Vite SPA in `frontend/`
- Current local env loading via `.env`

## 2. Requirements and Assumptions
- Goal: Make project Azure-hosting ready (not deploy yet)
- Preferred architecture: frontend and backend deployed separately
- Security: no secrets in source control; runtime config via Azure app settings

## 3. Selected Azure Recipe
- Recipe: AZD + Bicep
- Frontend target: Azure Static Web Apps
- Backend target: Azure App Service (Linux, Python)

## 4. Planned Changes
1. Add Azure deployment metadata (`azure.yaml`) at repo root.
2. Add App Service startup command and runtime settings files for Django backend.
3. Add production Django settings readiness for Azure:
   - environment-driven `SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`
   - HTTPS/security middleware toggles for production
   - optional CORS for frontend origin
4. Add backend dependency updates needed for production hosting.
5. Add deployment docs with exact Azure CLI/AZD steps and required app settings.
6. Add example env templates for backend/frontend (no secrets).

## 5. Security Plan
- Keep `.env` ignored in git.
- Use Azure App Service configuration for secrets:
  - `DJANGO_SECRET_KEY`
  - `GOOGLE_SAFE_BROWSING_API_KEY`
- Configure allowed hosts and CORS explicitly.

## 6. Validation Plan
- Run backend Django checks.
- Run frontend production build.
- Verify API endpoint locally after production-setting changes.

## 7. Handoff
- After preparation, status will be updated to `Ready for Validation`.
