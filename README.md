# User Authentication and Access Tracking System Backend

![Red Canary Logo](./red-canary-logo.png)

## Project Overview

This repository contains the backend of the "User Authentication and Access Tracking System with Database Integration and Email Alerts" project, developed for the Red Canary Software Engineer Take-Home Exam. The backend is built using Node.js, incorporating key functionalities such as user sign-up, sign-in, session management, and email notifications. The backend integrates with a database PostgreSQL to manage user data, track failed login attempts, and ensure secure access.

### Technologies Used

- **Node.js** (Express) - For server-side API development.
- **PostgreSQL** - To store user credentials, login attempts, and history. *(Only storing User Credentials implemented to date)*
- **JWT (JSON Web Tokens)** - To manage user authentication and session security. *(Not yet implemented)*
- **Redis** - For session management. *(Not yet implemented)*
- **Nodemailer** - To handle email notifications. *(Not yet implemented)*
- **Jest** - For unit, integration, and end-to-end testing. *(Not yet implemented)*

## Contents
- [Deployed Server Access](#deployed-server-access)
- [GitHub Repositories](#github-repositories)
- [Features](#features)
- [Database Design](#database-design)
- [Installation and Setup](#installation-and-setup)
- [Testing](#testing)
- [Deployment](#deployment)
- [Task Management](#task-management)
- [Challenges and Key Decisions](#challenges-and-key-decisions)
- [Conclusion](#conclusion)
- [License](#license)
- [Contact](#contact)

## Deployed Server Access
[Live Backend Server](https://dashboard.render.com/) *(place holder link)*

## GitHub Repositories
- [FrontEnd](https://github.com/jorammercado/red-canary-takehome-fe)
- [BackEnd](https://github.com/jorammercado/red-canary-takehome-be)

## Features

### User Authentication

- **Sign-Up:** Functionality to create new user accounts with appropriate data validation.
- **Sign-In:** Issue JWT tokens after successful user authentication. *(Currently implemented without JWT Token)*
- **Password Management:** Reset and update passwords securely. *(Not yet implemented)*
- **Rate Limiting:** Protect against brute-force attacks by limiting the number of login attempts. *(Not yet implemented)*

### Database Integration

- Users can be stored in **PostgreSQL**.
- User credentials, login attempts, and histories are logged to the chosen database. *(Only storing User credentials implemented to date)*

### Failed Login Tracking and Blocking *(Not yet implemented)*

- Track failed login attempts for each user.
- Block users after **three consecutive failed login attempts** and send email notifications informing them of the account lockout.
- **IP-based tracking** to prevent bypassing blocks by switching accounts.
- Email notification is sent when an account is locked.

### New Browser Login Notification *(Not yet implemented)*

- **Device Fingerprinting / IP Tracking:** Detect login attempts from new devices or browsers.
- **Email Notification:** Inform users of new browser logins with detailed information.

### Protected API Access *(Not yet implemented)*

- **Rate Limiting:** Block IPs that attempt to access an API endpoint with an invalid token more than five times.
- **JWT Verification:** Protect routes by verifying JWT tokens using middleware.
- **Sample Endpoint (/get-movies):** Returns static data to verify secure access.

### Multi-Factor Authentication (MFA) *(Not yet implemented)*

- Implemented MFA to provide an additional layer of security for user accounts.

### Account Unlock Automation *(Not yet implemented)*

- Automated system to unlock users after a specified lockout period (bonus feature).

## Installation and Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/red-canary-takehome-be.git
   cd red-canary-takehome-be
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
   PG_DATABASE=redcanary_dev
   PG_USER=postgres
   ```

4. Setup the PostgreSQL database:
   ```sh
   npm run db_schema
   ```

4. Run the server:
   ```sh
   npm start
   ```

## Testing *(Not yet implemented)*

Testing is a crucial part of the project to ensure reliability and security. This project includes the following tests:

### Unit Testing

- **Authentication and Authorization:** Tests for sign-up, sign-in, and token management.
- **JWT Generation and Verification:** Validates token creation, verification, and expiration.
- **Rate Limiting and Failed Login Tracking:** Ensures correct blocking and notification mechanisms.

### Integration Testing

- Tests interactions between the authentication service, database, and email notifications.
- Simulates scenarios such as **failed logins**, **new browser logins**, and **token expiry**.

### End-to-End Testing

- Simulates user workflows, including **sign-up**, **sign-in**, and interactions with protected APIs.
- Validates email notifications and session handling.

To run tests:
```sh
npm test
```

## Deployment

The application can be deployed using **Render.com**. Deployment instructions are included below for Render.com:

1. Create a new service in Render.
2. Connect the GitHub repository to Render.
3. Set up environment variables using the Render dashboard.
4. Deploy the server.



## Challenges and Key Decisions

- **Session Management:** Choosing Redis for session management helped ensure efficiency and speed in handling user sessions.
- **Security:** Implementing **rate limiting**, **JWT protection**, and **MFA** was crucial to preventing unauthorized access.
- **Testing:** A significant focus was placed on ensuring comprehensive test coverage across unit, integration, and end-to-end testing.

## Conclusion

This project was a comprehensive exercise in building a secure user authentication system, integrating database storage, and implementing best practices for access tracking. The focus was on enhancing security, reliability, and scalability, while ensuring efficient session management and appropriate user notifications.

## License
This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/license/mit) file for details.

## Contact
For any inquiries or feedback, please contact:

- Joram Mercado: [GitHub](https://github.com/jorammercado), [LinkedIn](https://www.linkedin.com/in/jorammercado)
