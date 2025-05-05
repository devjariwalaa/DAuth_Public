# DAuth - Scalable Authentication System

DAuth is a robust authentication system built using **FastAPI** and **PostgreSQL**.  
It provides **JWT-based authentication**, **OAuth2 login**, and is designed to be **scalable** with a microservices architecture.

I learned technologies and plan to improve my knowledge in **FastAPI** and build solid APIs. 

## Features

### Phase 1 (Completed) - Basic Authentication
- User **Registration** (`POST /auth/signup`)
- User **Login** (`POST /auth/login`)
- **JWT-based authentication** (`GET /auth/protected`)
- **Authorization Headers (No Query Params)**
- **Account Management Features:**
  - **Delete Account** (`DELETE /auth/delete`)
  - **Change Password** (`PUT /auth/change-password`)
- **Security Enhancements:**
  - Ensured password updates reflect in login
  - Removed raw passwords from API responses

### Phase 2 - OAuth2 & Security Enhancements (Completed)
- Implement **OAuth2 login** (Google, GitHub, etc.)
- **Refresh Tokens** (Handle JWT expiration)
- **Rate Limiting** (Prevent brute force attacks)
- **Token Security Enhancements** (Revocation, expiry handling)

### Phase 3 - Microservices Expansion -- COMING SOON
- **Split Auth Service & User Service**
- **Docker & Containerization**
- **API Gateway for service routing**

### Phase 4 - Scaling & Deployment -- COMING SOON
- **Deploy using Kubernetes & Cloud Hosting**
- **Monitoring & Logging**
- **Optimize for large-scale usage (100k+ users)**

---
