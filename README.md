Product Hunt Backend API

a role base authentication include user , admin , superadmin

A Node.js + Express backend application for handling authentication, payments, and database operations for a Product Hunt–style platform.

📦 Tech Stack

Node.js

Express.js

MongoDB

JWT Authentication

Stripe Payment Gateway

SSLCommerz Payment Gateway

Axios

CORS

Dotenv

📁 Project Structure
product-hunt/
│
├── index.js
├── .env
├── package.json
└── README.md
📥 Installation

Clone the repository:

git clone <your-repo-url>
cd product-hunt

Install dependencies:

npm install

Create a .env file in the root directory and add:

PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
STRIPE_SECRET_KEY=your_stripe_secret_key
SSLCOMMERZ_STORE_ID=your_store_id
SSLCOMMERZ_STORE_PASSWORD=your_store_password

Start the server:

npm start

Server will run on:

http://localhost:5000
📜 Available Scripts
npm start      # Run server
npm test       # Default test script
📦 Dependencies
Package	Purpose
axios	HTTP requests
cors	Enable cross-origin requests
dotenv	Environment variable management
express	Backend framework
jsonwebtoken	Authentication (JWT)
mongodb	MongoDB database driver
sslcommerz-lts	SSLCommerz payment integration
stripe	Stripe payment integration
🔐 Authentication

Uses JWT (JSON Web Token)

Token-based protected routes

Middleware for verifying tokens

💳 Payment Integration
Stripe

Create payment intent

Handle payment confirmation

SSLCommerz

Initiate payment session

Validate payment

🛠 API Features (Example)

User registration & login

JWT token generation

Protected routes

Product CRUD operations

Payment processing

🌍 Environment Variables

Make sure to configure the following variables in your .env file:

PORT
MONGODB_URI
JWT_SECRET
STRIPE_SECRET_KEY
SSLCOMMERZ_STORE_ID
SSLCOMMERZ_STORE_PASSWORD
