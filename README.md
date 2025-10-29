# User Authentication and Access Tracking System Backend

## Project Overview

This repository contains the backend for the **User Authentication and Access Tracking System with Database Integration and Email Alerts** project. Built with **Express.js**, the backend provides robust user authentication, multi-factor authentication (MFA), JWT-based session management, account lockout functionality, and email notifications. It integrates with **PostgreSQL** to manage user data, log login attempts, and enforce secure access control.

### 🚀 Technologies Used

* **Node.js** (Express) – Server-side API development
* **PostgreSQL** – Persistent storage for user credentials, login activity, and blocklists
* **JWT (JSON Web Tokens)** – Session authentication using signed tokens
* **bcryptjs** – Password hashing and credential validation
* **Redis** – In-memory store for rate limiting and temporary blocks
* **Nodemailer** – Email service integration

## 📑 Contents

* [Deployed Server Access](#deployed-server-access)
* [GitHub Repositories](#github-repositories)
* [Features](#features)
* [Installation and Setup](#installation-and-setup)
* [Testing](#testing)
* [License](#license)
* [Contact](#contact)

## 🌐 Deployed Server Access

* **Live Backend Server**: [https://auth-access-tracker-be.onrender.com/](https://auth-access-tracker-be.onrender.com/)

## 💻 GitHub Repositories

* **Frontend**: [auth-access-tracker-fe](https://github.com/jorammercado/auth-access-tracker-fe)
* **Backend**: [auth-access-tracker-be](https://github.com/jorammercado/auth-access-tracker-be)

## 🔐 Features

### User Authentication

* **Sign-Up**: Users can register new accounts with input validation. Passwords are hashed using bcrypt.
* **Sign-In**: Credentials are validated using bcrypt. Upon successful verification, a JWT token is issued for session-based access.
* **Password Management**:

  * **Forgot Password Flow**: Tokenized reset link sent via email. The link directs users to a reset form and expires after 2 minutes.
  * **Password Update (While Logged In)**: Requires a valid JWT token and revalidation of the current password using bcrypt.
* **Authentication**:

  * **JWT-based**: Authenticates requests to protected routes (e.g., profile updates, account deletion).
  * **bcrypt-based**: Used during login, password changes, and OTP verification.

### Database Integration

**PostgreSQL** manages structured data for user accounts and activity logs. Key tables include:

* **Users**: Stores credentials, profile info, and MFA settings.
* **Login Attempts**: Logs attempts with timestamps, success flags, IPs, and fingerprints.
* **Login History**: Records successful logins with device/browser info.
* **Blocked IPs**: Tracks IPs temporarily blocked after repeated failures.

#### Rationale

This schema follows a **separation of concerns** approach, simplifying auditing, scaling, and security maintenance.

### Login Protection and Blocking Mechanisms

This system uses layered safeguards to prevent unauthorized access:

* **User-Based Lockout**: Locks an account after **3 consecutive failed login attempts**, and sends an alert email.
* **IP-Based Blocking**: Blocks all login attempts from the same IP after **7 consecutive failed attempts**.
* **Rate Limiting (Redis)**: Restricts **5 failed attempts within 8 seconds** based on IP and device fingerprint.

⏱ In all three cases, the block duration is set to **30 seconds** for development and debugging purposes.

### New Browser Login Notification

* Uses fingerprinting and IP tracking to detect unfamiliar logins.
* Sends an **email alert** with metadata when a new browser/device logs in.

### Protected API Access

* Middleware ensures that JWT tokens are valid and active for accessing protected endpoints.

### Multi-Factor Authentication (MFA)

* After login, users receive a **6-digit OTP via email**.

  * OTP is hashed using bcrypt and expires after **3 minutes**.
  * Validation requires a match and a valid expiration timestamp.

### Account Unlock and Password Reset Automation

#### Forgot Password & Reset Flow

* **Initiate Reset**: Users submit their email via a public form.
* **Tokenized Email Link**: A hashed reset token is emailed and expires in **2 minutes**.
* **Anonymous Message**: Generic success messages prevent disclosure of user existence.
* **Reset Page**: Users access a password update form via the link.
* **Password Update**: The token is verified, new password validated and hashed with bcrypt.
* **Redirect**: Successful resets redirect to the login page.

## ⚙️ Installation and Setup

1. **Clone the repository**:

   ```sh
   git clone https://github.com/your-username/auth-access-tracker-be.git
   cd auth-access-tracker-be
   ```

2. **Install dependencies**:

   ```sh
   npm install
   ```

3. **Configure environment variables** by creating a `.env` file:

   ```env
   PORT=8899
   PG_HOST=localhost
   PG_PORT=5432
   PG_DATABASE=auth_access_tracker_dev
   PG_USER=postgres
   JWT_SECRET=your_jwt_secret
   EMAIL_USER=your_email@example.com
   EMAIL_PASS=your_email_password
   CLIENT_URL=http://localhost:5173
   REDIS_URL=redis://...
   REDIS_PASSWORD=your_redis_password
   ```

   > 🔑 To generate a JWT secret, run:
   >
   > ```sh
   > node generateJwtSecret.js
   > ```
   >
   > 🔐 For Redis setup, create a Redis instance on [Redis Cloud](https://cloud.redis.io/) and retrieve credentials.

4. **Set up the PostgreSQL database**:

   ```sh
   npm run db_schema
   npm run db_seed
   ```

5. **Start the server**:

   ```sh
   npm start
   ```

## 🧪 Testing

**Preliminary Testing Exposure**: Basic unit tests using `supertest` were implemented to validate core routing logic and server responses.

```sh
npm test
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/license/mit) file for more details.

## 📬 Contact

For any inquiries or feedback, please contact:

* **Joram Mercado**: [GitHub](https://github.com/jorammercado) | [LinkedIn](https://www.linkedin.com/in/jorammercado)
