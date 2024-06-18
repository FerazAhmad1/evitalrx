# Project - User Registration

## Setup

### Server Setup

#### Clone Repository

```bash
git clone https://github.com/FerazAhmad1/evitalrx.git


cd evitalrx
```

```bash
npm install
```

1. Create a config.env file at the root level of the project.

2. Add the following environment variables to config.env:

```ini
PASSWORD=your_mysql_database_password
NODE_ENV=development
USER=your_mysql_database_username
JWT_SECRET=your_jwt_secret_string_must_be_at_least_32_characters
JWT_EXPIRES_IN=90d
JWT_COOKIE_EXPIRE_IN=90
DB_NAME=evitalRX
DB_HOST=localhost
PORT=3000
DIALECT=mysql
EMAIL_HOST=smtp_host_like_sandbox.smtp.mailtrap.io
EMAIL_PORT=smtp_port_number_like_2525
EMAIL_USERNAME=smtp_username
EMAIL_PASSWORD=smtp_password
```

Database Setup:

Create a database schema named evitalRx.
Run the Server:

```bash
npm start

```

## Endpoints

1. Signup API
   ```bash
   https://localhost:3000/api/v1/user/signup
   ```
   Request body
   
   ```json
      {
        "name": "Feraz Ahmad",
        "mobile": "6207571009",
        "email": "khanferaz546@gmail.com",
        "dob": "01-12-1995",
        "gender": "male",
        "address": "semra,gopalganj",
        "password": "1234567890"
      }
    ```
    Response

    ```json
    {
    "success": true,
    "otp": "217896",
    "link": "http://127.0.0.1:3000/api/v1/user/verifyotp",
    "messge": "check your email "
    }
    ```
  2. Verify OTP
     ```bash
      https://localhost:3000/api/v1/user/verifyotp
     ```
     Request body
     
       ```json
        {
          "email": "khanferaz546@gmail.com",
          "otp": "217896"
        }
       ```
    
      Response
    
      ```json
        {
            "success": true,
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImtoYW5mZXJhejU0NkBnbWFpbC5jb20iLCJpYXQiOjE3MTg2ODM1MTAsImV4cCI6MTcyNjQ1OTUxMH0.2JFR3BKs1uaqJL03F2_PIvxhYXcaVP9mDEmkS4yugh8"
        }
      ```


  3. Login API
     ```bash
      https://localhost:3000/api/v1/user/login
     ```
     Request body
     
       ```json
        {
          "email": "khanferaz546@gmail.com",
          "password": "1234567890"
        }
       ```
    
      Response
    
      ```json
        {
            "success": true,
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImtoYW5mZXJhejU0NkBnbWFpbC5jb20iLCJpYXQiOjE3MTg2ODM1MTAsImV4cCI6MTcyNjQ1OTUxMH0.2JFR3BKs1uaqJL03F2_PIvxhYXcaVP9mDEmkS4yugh8"
        }
      ```

  4. Forgot password API
     ```bash
      https://localhost:3000/api/v1/user/forgotpassword
     ```
     Request body
     
       ```json
        {
          "email": "khanferaz546@gmail.com"
        }
       ```
    
      Response
    
      ```json
        {
        "success": true,
        "message": "reset link has been sent to your registred email"
      }
      ```
  5. Update Profile API
     ```bash
      https://localhost:3000/api/v1/user/updateprofile
     ```
     Request body
     
       ```json
        {
          "password": "123456789000"
        }
       ```
    
      Response
    
      ```json
        {
          "success": true,
          "message": "password , has been update successfully"
        }
      ```
