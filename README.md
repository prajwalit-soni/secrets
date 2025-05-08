Project Deploy link https://secrets-c58j.onrender.com/
# Secrets App

The **Secrets App** is a secure platform for users to register, log in, and share secrets anonymously. It uses modern web technologies and follows best practices for authentication and security.

## Features
- User registration with password validation and hashing.
- Secure login with JWT-based authentication.
- Protected routes accessible only to authenticated users.
- Password strength validation and error handling.
- Rate limiting and security headers for enhanced protection.

## Technologies Used
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Authentication**: JWT (JSON Web Tokens), bcrypt.js for password hashing
- **View Engine**: EJS (Embedded JavaScript)
- **Security**: Helmet.js, express-rate-limit
- **Environment Variables**: dotenv

---

## Installation and Setup

Follow these steps to set up and run the project locally:

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (running locally or a connection URI)
- Git (optional)

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/secrets-app.git
cd secrets-app
# secrets
