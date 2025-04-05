# User Authentication and Access Tracking System Backend

## Project Overview

This repository contains the backend for the **User Authentication and Access Tracking System with Database Integration and Email Alerts** project. Built with Express.js, the backend provides robust user authentication, multi-factor authentication (MFA), JWT-based session management, account lockout functionality, and email notifications. It integrates with PostgreSQL to manage user data, log login attempts, and enforce secure access control.

### Technologies Used

- **Node.js** (Express) - Server-side API development
- **PostgreSQL** - Persistent storage for user credentials, login activity, and blocklists
- **JWT (JSON Web Tokens)** - Session authentication using signed tokens
- **bcryptjs** - Password hashing and credential validation
- **Redis** - In-memory store for rate limiting and temporary blocks
- **Nodemailer** - Email service integration

## Contents

- [Deployed Server Access](#deployed-server-access)
- [GitHub Repositories](#github-repositories)
- [Features](#features)
- [Installation and Setup](#installation-and-setup)
- [Testing](#testing)
- [License](#license)
- [Contact](#contact)

## Deployed Server Access

- **Live Backend Server**: [https://auth-access-tracker-be.onrender.com/](https://auth-access-tracker-be.onrender.com/)

## GitHub Repositories

- Frontend: [auth-access-tracker-fe](https://github.com/jorammercado/auth-access-tracker-fe)
- Backend: [auth-access-tracker-be](https://github.com/jorammercado/auth-access-tracker-be)

## Features

### User Authentication

- **Sign-Up**: Allows users to register new accounts with input validation. Passwords are hashed using bcrypt.
- **Sign-In**: Credentials are validated using bcrypt. Upon successful verification, a JWT token is issued for session-based access.
- **Password Management**:
  - **Forgot Password Flow**: Uses a tokenized reset link sent via email. The link directs users to a page where they can submit a new password. The token and time window to update the password on this page expires after 2 minutes.
  - **Password Update (While Logged In)**: Requires both a valid JWT token and revalidation of the user's current password via bcrypt.
- **Authentication**:
  - **JWT-based**: Used to authenticate protected routes' requests after login (e.g., profile update, account deletion).
  - **bcrypt-based**: Used when validating credentials, such as login, password change, or OTP verification.

### Database Integration

**PostgreSQL** manages structured data for user accounts and activity logs. Key tables:

- **Users**: Stores credentials, profile info, and MFA settings.
- **Login Attempts**: Logs each attempt with timestamp, success flag, IP, and fingerprint.
- **Login History**: Records successful logins with device/browser info.
- **Blocked IPs**: Tracks IPs temporarily blocked due to repeated failures.

#### Rationale

This schema supports **separation of concerns**, making it easier to audit, scale, and extend while minimizing security risks.

### Login Protection and Blocking Mechanisms

This system uses layered safeguards to prevent unauthorized access:

- **User-Based Lockout**: Locks individual accounts after **3 consecutive failed login attempts**. An email alert is sent to notify the user.
- **IP-Based Blocking**: Prevents circumvention by switching usernames. Blocks any and all accounts from logging in after **7 consecutive failed attempts** from that same IP—regardless of time frame.
- **Rate Limiting (Redis)**: Enforces a cap of **5 failed attempts within 8 seconds** based on IP and device fingerprint. Redis ensures fast enforcement and temporary access blocks.

In all three cases, the account, IP, or device remains blocked for **30 seconds**—a duration set for development and debugging purposes.

### New Browser Login Notification

- Detects new device/browser logins using fingerprinting and IP tracking.
- Sends an **email alert** with relevant login metadata to notify users of unrecognized access.

### Protected API Access

- Middleware enforces JWT token verification for all protected endpoints. If the token is invalid or expired, access is denied.

### Multi-Factor Authentication (MFA)

- Sends a **6-digit OTP via email** after successful login with email and password.
  - OTP is hashed using bcrypt and expires after **3 minutes**.
  - Verification requires a correct OTP match and valid expiration timestamp.

### Account Unlock and Password Reset Automation

#### Forgot Password & Reset Flow

- **Initiate Reset**: Users who forget their password can submit their email via a public form.
- **Tokenized Email Link**: A reset token is generated, hashed, and sent to the user's email. It expires in **2 minutes**.
- **Anonymous Message**: If no matching account is found, a generic success message is returned to avoid information disclosure.
- **Reset Page**: Users follow the emailed link to access a form.
- **Password Update**: If the token is correctly verified, the new password is validated, hashed with bcrypt, and stored securely.
- **Redirect**: Upon success, users are redirected to the login page.

## Installation and Setup

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

## Testing

Basic unit tests are included and can be run with:

```sh
npm test
```

Manual testing was conducted during development. Additional automated testing (integration and end-to-end) is planned for future updates.

## License

This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/license/mit) file for more details.

## Contact

For any inquiries or feedback, please contact:

- Joram Mercado: [GitHub](https://github.com/jorammercado), [LinkedIn](https://www.linkedin.com/in/jorammercado)