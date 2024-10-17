
DROP DATABASE IF EXISTS redcanary_dev;
CREATE DATABASE redcanary_dev;

\c redcanary_dev;

CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    firstname VARCHAR(50) NOT NULL DEFAULT 'first name unknown',
    lastname VARCHAR(50) NOT NULL DEFAULt 'last name unknown',
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_img TEXT DEFAULT 'profile image',
    about TEXT DEFAULT 'about me',
    dob VARCHAR(20) DEFAULT '1/1/2024',
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE login_attempts (
    attempt_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    success BOOLEAN NOT NULL,
    device_fingerprint TEXT
);

CREATE TABLE login_history (
    history_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    device_fingerprint TEXT
);