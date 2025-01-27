# User Authentication and Access Tracking System Backend

## Project Overview

The backend Repo for the "User Authentication and Access Tracking System" with database integration and email alerts project. Built with Express.js, the backend offers features like user sign-up, sign-in, multi-factor authentication, rate limiting with Redis, JWT tokens, account lock functionality, and email notifications. It integrates with PostgreSQL to manage user data, track login attempts, and ensure secure access.

### Technologies Used

- **Node.js** (Express) - For server-side API development.
- **PostgreSQL** - To store user credentials, login attempts, blocked ips and history.
- **JWT (JSON Web Tokens)** - To manage user authentication and session security. 
- **Redis** - Used for rate limiting to prevent brute force attacks.
- **Nodemailer** - To handle email notifications. 

## Contents
- [Deployed Server Access](#deployed-server-access)
- [GitHub Repositories](#github-repositories)
- [Features](#features)
- [Installation and Setup](#installation-and-setup)
- [License](#license)
- [Contact](#contact)

## Deployed Server Access
[Live Backend Server](https://red-canary-takehome-be.onrender.com/) 

## GitHub Repositories
- [frontend: auth-access-tracker-fe](https://github.com/JoramAMercado/auth-access-tracker-fe)
- [backend: auth-access-tracker-be](https://github.com/JoramAMercado/auth-access-tracker-be)

## Features

### User Authentication
- **Sign-Up:** Allows users to create new accounts with data validation to ensure correctness.

- **Sign-In:**  Issues JWT tokens for successful user authentication, with a session limit of 10 minutes (for testing and debugging purposes). 

- **Password Management:** Provides secure password reset and update features via a reset email link, which includes a time limit and password re-verification for added security, respectively. 

- **Rate Limiting:** Protects against brute-force attacks by limiting login attempts. Uses Redis (for quick access to non-persistent RAM memory) to track IP addresses and device fingerprints.
  - The rate limiting blocks an IP address or device fingerprint if **5 failed login attempts** occur within a specified time frame (e.g., **8 seconds**).
  - Once blocked, the IP or device remains blocked for **30 seconds**, times chosen for development and debugging purposes.

### Database Integration
- **PostgreSQL** is used to store user data and track activity.

- The following key tables are implemented:
  - **Users**: Stores user details such as username, email, password, profile information, and multi-factor authentication (MFA) data.

  - **Login Attempts**: Tracks each login attempt, including the user, timestamp, IP address, success status, and device fingerprint.

  - **Login History**: Logs successful logins, capturing user, timestamp, IP address, and device details.

  - **Blocked IPs**: Manages IP addresses that are blocked after multiple failed login attempts, with fields for expiration and related user information.
  
#### Why This Structure?
This database structure was chosen for **modularity** and **separation of concerns**. Each table has a specific purpose, which ensures that the system can manage data effectively and securely. 

It also improves **maintainability** since each table handles a distinct aspect of user management, allowing for easier updates or adjustments without affecting other parts of the database.

Overall, this structure enhances scalability, security, and makes the system more robust against potential misuse or vulnerabilities.

### Failed Login Tracking and Blocking 
- Track failed login attempts for each user.

- Block users after **three consecutive failed login attempts**.

- **IP-based blocking** prevents users from bypassing blocks by switching accounts, distinct from rate limiting. This mechanism ensures that even if users switch accounts, their IP remains blocked. The block is triggered after 7 consecutive failed login attempts from the same IP address. Access is restored after 30 seconds for a single attempt, and the blocking system resets after a successful login.

### New Browser Login Notification 
- **Device Fingerprinting / IP Tracking**: Detect login attempts from new devices or browsers using IP addresses and device fingerprints.

- **Email Notification**: Notify users via email when a new browser or device login is detected, providing details about the login to help identify potential misuse or unauthorized access.

### Protected API Access 
- **JWT Verification**: Middleware is used to verify JWT tokens for protected routes, denying requests immediately if the token is invalid.

### Multi-Factor Authentication (MFA)

- **MFA Implementation**: Provides an additional layer of security for user accounts by requiring a second verification step.

- **How it Works**: When a user logs in with a valid email-password pair, they receive a One-Time Password (OTP) via email.
  - The OTP is a 6-digit code that expires in **3 minutes**.
  - The user must enter this code on the verification page to complete the login process and access their profile.

- **Enhanced Security**: This process helps ensure that even if a user's credentials are compromised, access is still protected by requiring the second authentication factor.


### Account Unlock and Password Reset Automation

- **Forgot Password Page**: Users who forget their password can navigate to a dedicated page to initiate the reset process.

- **Email Verification**: After entering their email, a message informs the user that, if an account is associated with this email, a reset link has been sent.

- **Reset Link with Expiration**: The reset link contains a token and expires in **2 minutes**.

- **Password Reset Page**: By clicking on the link in their email, users are directed to a password reset page where they can enter a new password.

- **Successful Reset**: Once the password is updated, users are redirected to the login page to access their account with the new credentials.

- **Account Lockout**: Users who enter incorrect credentials **three consecutive times** will be locked out, even if they later enter the correct email-password pair. This lockout is automatically lifted after **30 seconds**, and the user is notified by email that their account has been temporarily locked due to multiple failed attempts.


## Installation and Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/auth-access-tracker-be.git
   cd auth-access-tracker-be
   ```

2. Install dependencies:
   ```sh
   npm install
   ```

3. Set up environment variables by creating a `.env` file:
   ```sh
   PORT=8899
   PG_HOST=localhost
   PG_PORT=5432
   PG_DATABASE=auth_access_tracker_dev
   PG_USER=postgres
   JWT_SECRET=
   EMAIL_USER=
   EMAIL_PASS=
   CLIENT_URL=http://localhost:5173
   REDIS_URL=redis://
   REDIS_PASSWORD=
   ```
   > **Note:** To obtain the `REDIS_URL` and `REDIS_PASSWORD`, you need to set up an account with [Redis Cloud](https://cloud.redis.io/) and create an instance.
   > To generate the `JWT_SECRET`, run the following command:
   > ```sh
   > node generateJwtSecret.js
   > ```
   > For `EMAIL_USER` and `EMAIL_PASS`, enter a Google email and password. You may need to modify your account security settings to allow access from third-party apps.

4. Setup the PostgreSQL database:
   ```sh
   npm run db_schema
   npm run db_seed
   ```

4. Run the server:
   ```sh
   npm start
   ```

## Testing 
Testing is crucial for ensuring the reliability and security of this project. In the initial stage of development, comprehensive manual testing was conducted. To further enhance robustness, security, and development speed, automated testing will be implemented in phases, beginning with unit tests, followed by integration and end-to-end testing.

**Unit Testing**: Some unit tests have been implemented as a starting point. More work is needed to achieve comprehensive coverage.


## License
This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/license/mit) file for details.

## Contact
For any inquiries or feedback, please contact:

- Joram Mercado: [GitHub](https://github.com/joramamercado), [LinkedIn](https://www.linkedin.com/in/JoramAMercado)
