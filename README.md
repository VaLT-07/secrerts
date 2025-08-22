# Secrets — Minimal Secure Auth App (No DB)

Features
- Registration with name, email, password (validated)
- Password hashing (bcrypt)
- Login with JWT stored in HttpOnly cookie
- Protected dashboard, ability to post/view personal 'secrets'
- Attractive Bootstrap UI
- File-based persistence: `data/users.json`, `data/secrets.json`

Run
```
npm install
cp .env.example .env
npm start
```
Open http://localhost:3000
Demo user created automatically if no users exist: demo@example.com / DemoPass1

.env.example
```
JWT_SECRET=change_me
NODE_ENV=development
PORT=3000
```

Notes: For production use a real DB and stronger secret. This repo is for demo and learning purposes.
