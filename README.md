# 🛰️ CrimeSpot

CrimeSpot is a full-stack, real-time crime hotspot detection and analysis system.
It combines an interactive frontend, a secure backend API, and AI-powered analytics to map crime-prone zones, alert users, and support law-enforcement decision making.

This monorepo contains both the **frontend** (web UI) and **backend** (APIs, data processing, hotspot engine).

---

## 📁 Repository Layout

CrimeSpot/
frontend/        # Web App (React / Vite)
backend/         # API Server (Node / Python backend)

---

## 🚀 Features (High Level)

### 🔍 1. Crime Data Ingestion
- Add, edit, delete incidents (admin only)
- Store crime type, location, time, metadata
- Secure validation & role-based access

### 🗺️ 2. Crime Hotspot Detection
- Uses clustering algorithms (future: ML models)
- Displays intensity zones on the map
- Real-time updates based on new incidents

### 👤 3. User & Admin System
- JWT-based authentication
- Roles:
  - Admin → Full CRUD operations on crime data
  - User → View hotspots, receive warnings
- Secure route protection on backend

### 📡 4. Frontend (Web Application)
- Modern UI for:
  - Viewing hotspots
  - Viewing crime lists
  - Admin dashboard
  - Adding crime records
- Map integration using Leaflet / Mapbox / Google Maps (your choice)

### 🔔 5. Alert System
- Notifies users if they enter a high-risk zone (future mobile app support)

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

git clone https://github.com/Sathiyanryn/CrimeSpot.git
cd CrimeSpot

---

## 🖥️ Frontend Setup (React)

cd frontend
npm install
npm run dev

Environment variables:

Create frontend/.env:

VITE_API_BASE_URL=http://localhost:5000/api

---

## 🔧 Backend Setup (NodeJS or Python)

### If Node.js:
cd backend
npm install
npm run dev

### If Python:
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py

Create backend/.env:

PORT=5000
DATABASE_URL=mongodb://localhost:27017/crimespot
JWT_SECRET=YOUR_SECRET_KEY

---

## 🔗 API Overview (Example)

POST /api/auth/login — Login & get token  
POST /api/auth/register — Register user  
GET  /api/crimes — List all crimes  
POST /api/crimes — Add crime (admin)  
PUT  /api/crimes/:id — Update crime  
DELETE /api/crimes/:id — Delete crime  
GET  /api/hotspots — Get hotspot data  
GET  /api/alerts — Risk alerts  

---

## 🛡️ Authentication & Security

- JWT-based authentication  
- Hashed passwords (bcrypt recommended)  
- Admin-only routes protected  
- CORS configured properly  
- Environment variables secured using .env  

---
