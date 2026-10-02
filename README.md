# Prodigy InfoTech - Backend Development Internship

## Task 03: JWT-Based Authentication & Role-Based Authorization (RBAC)

Implements stateless authentication and access control for RESTful services using **JSON Web Tokens (JWT)**, **bcrypt** password hashing, and role checks in **FastAPI** with **MySQL**.

### Key Features
* **Stateless Authentication**: Signed JWT tokens issued upon successful login.
* **Password Security**: Bcrypt salted hashing prevents plaintext exposure.
* **Protected Routes**: Custom dependency injection (`HTTPBearer`) validates token expiry and signatures.
* **Role-Based Access Control (RBAC)**:
  * `/users/me`: Authenticated profile endpoint.
  * `/admin/users`: Enforces `admin` role authorization, returning `403 Forbidden` for standard users.

### Setup Instructions
1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # On Git Bash Windows