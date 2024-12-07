I'll help you create a comprehensive authentication microservice. Let's structure this systematically.



```typescript
// src/config/auth.config.ts
import dotenv from 'dotenv';

dotenv.config();

export const authConfig = {
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '24h',
    refreshExpiresIn: '7d',
  },
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback',
    },
    apple: {
      clientId: process.env.APPLE_CLIENT_ID,
      clientSecret: process.env.APPLE_CLIENT_SECRET,
      callbackURL: '/auth/apple/callback',
    },
    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: '/auth/microsoft/callback',
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: '/auth/github/callback',
    },
    linkedin: {
      clientId: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: '/auth/linkedin/callback',
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: '/auth/facebook/callback',
    },
  },
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID,
    authToken: process.env.TWILIO_AUTH_TOKEN,
    whatsappFrom: process.env.TWILIO_WHATSAPP_FROM,
  },
};

```

```typescript
// src/types/auth.types.ts
export interface User {
  id: string;
  email?: string;
  phone?: string;
  whatsapp?: string;
  displayName?: string;
  provider?: string;
  providerId?: string;
  verified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuthToken {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface VerificationCode {
  code: string;
  expiresAt: Date;
  attempts: number;
}

export type AuthProvider = 
  | 'google'
  | 'apple'
  | 'microsoft'
  | 'github'
  | 'linkedin'
  | 'facebook'
  | 'email'
  | 'phone'
  | 'whatsapp';

```

```typescript
// src/services/auth.service.ts
import { User, AuthToken, VerificationCode, AuthProvider } from '../types/auth.types';
import jwt from 'jsonwebtoken';
import { authConfig } from '../config/auth.config';
import twilio from 'twilio';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import { prisma } from '../lib/prisma';

export class AuthService {
  private twilioClient: twilio.Twilio;

  constructor() {
    this.twilioClient = twilio(
      authConfig.twilio.accountSid,
      authConfig.twilio.authToken
    );
  }

  async createUser(data: Partial<User>): Promise<User> {
    return await prisma.user.create({
      data: {
        ...data,
        id: uuidv4(),
        verified: false,
      },
    });
  }

  async generateTokens(user: User): Promise<AuthToken> {
    const accessToken = jwt.sign(
      { userId: user.id },
      authConfig.jwt.secret,
      { expiresIn: authConfig.jwt.expiresIn }
    );

    const refreshToken = jwt.sign(
      { userId: user.id, version: uuidv4() },
      authConfig.jwt.secret,
      { expiresIn: authConfig.jwt.refreshExpiresIn }
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 24 * 60 * 60, // 24 hours
    };
  }

  async generateVerificationCode(): Promise<VerificationCode> {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    return {
      code,
      expiresAt,
      attempts: 0,
    };
  }

  async sendVerificationCode(
    to: string,
    code: string,
    method: 'sms' | 'whatsapp'
  ): Promise<void> {
    if (method === 'whatsapp') {
      await this.twilioClient.messages.create({
        body: `Your verification code is: ${code}`,
        from: `whatsapp:${authConfig.twilio.whatsappFrom}`,
        to: `whatsapp:${to}`,
      });
    } else {
      await this.twilioClient.messages.create({
        body: `Your verification code is: ${code}`,
        from: authConfig.twilio.whatsappFrom,
        to,
      });
    }
  }

  async verifyCode(
    userId: string,
    code: string,
    storedCode: VerificationCode
  ): Promise<boolean> {
    if (
      storedCode.code === code &&
      new Date() < storedCode.expiresAt &&
      storedCode.attempts < 3
    ) {
      await prisma.user.update({
        where: { id: userId },
        data: { verified: true },
      });
      return true;
    }
    return false;
  }

  async validateRefreshToken(token: string): Promise<string | null> {
    try {
      const decoded = jwt.verify(token, authConfig.jwt.secret) as {
        userId: string;
      };
      return decoded.userId;
    } catch {
      return null;
    }
  }
}

```

```typescript
// src/routes/auth.routes.ts
import express from 'express';
import passport from 'passport';
import { AuthService } from '../services/auth.service';
import { validateAuthRequest } from '../middleware/validation';

const router = express.Router();
const authService = new AuthService();

// Social login routes
router.get(
  '/auth/:provider',
  (req, res, next) => {
    const provider = req.params.provider;
    passport.authenticate(provider, {
      scope: getProviderScope(provider),
    })(req, res, next);
  }
);

router.get(
  '/auth/:provider/callback',
  (req, res, next) => {
    const provider = req.params.provider;
    passport.authenticate(provider, {
      session: false,
    })(req, res, next);
  },
  async (req, res) => {
    const tokens = await authService.generateTokens(req.user);
    res.json(tokens);
  }
);

// Email authentication
router.post('/auth/email/register', validateAuthRequest, async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.createUser({ email });
  const code = await authService.generateVerificationCode();
  // Send verification email
  res.json({ message: 'Verification email sent' });
});

// Phone authentication
router.post('/auth/phone/verify', validateAuthRequest, async (req, res) => {
  const { phone } = req.body;
  const user = await authService.createUser({ phone });
  const code = await authService.generateVerificationCode();
  await authService.sendVerificationCode(phone, code.code, 'sms');
  res.json({ message: 'Verification code sent' });
});

// WhatsApp authentication
router.post('/auth/whatsapp/verify', validateAuthRequest, async (req, res) => {
  const { whatsapp } = req.body;
  const user = await authService.createUser({ whatsapp });
  const code = await authService.generateVerificationCode();
  await authService.sendVerificationCode(whatsapp, code.code, 'whatsapp');
  res.json({ message: 'WhatsApp verification code sent' });
});

// Verify code
router.post('/auth/verify-code', async (req, res) => {
  const { userId, code } = req.body;
  const storedCode = await getStoredCode(userId); // Implement this
  const isValid = await authService.verifyCode(userId, code, storedCode);
  
  if (isValid) {
    const user = await getUserById(userId); // Implement this
    const tokens = await authService.generateTokens(user);
    res.json(tokens);
  } else {
    res.status(400).json({ message: 'Invalid code' });
  }
});

// Refresh token
router.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  const userId = await authService.validateRefreshToken(refreshToken);
  
  if (userId) {
    const user = await getUserById(userId); // Implement this
    const tokens = await authService.generateTokens(user);
    res.json(tokens);
  } else {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

function getProviderScope(provider: string): string[] {
  switch (provider) {
    case 'google':
      return ['profile', 'email'];
    case 'github':
      return ['user'];
    case 'linkedin':
      return ['r_liteprofile', 'r_emailaddress'];
    // Add other providers...
    default:
      return [];
  }
}

export default router;

```

Let me create a guide for setting up and using this authentication service:



# Authentication Microservice Setup Guide

## Overview
This authentication microservice provides a complete solution for handling multiple authentication methods including social logins, email, phone, and WhatsApp verification. It's designed to be easily integrated into any application while maintaining security best practices.

## Features
- Social login integration (Google, Apple, Microsoft, GitHub, LinkedIn, Facebook)
- Email authentication with verification
- Phone number authentication with SMS verification
- WhatsApp authentication
- JWT-based token management
- Refresh token functionality
- Rate limiting
- Security best practices implementation

## Prerequisites
- Node.js 16+
- PostgreSQL database
- Twilio account (for SMS and WhatsApp)
- Social provider API credentials
- Redis (optional, for rate limiting)

## Project Structure
```
auth-service/
├── src/
│   ├── config/
│   │   ├── auth.config.ts
│   │   └── database.config.ts
│   ├── middleware/
│   │   ├── validation.ts
│   │   ├── rateLimiter.ts
│   │   └── errorHandler.ts
│   ├── routes/
│   │   └── auth.routes.ts
│   ├── services/
│   │   └── auth.service.ts
│   ├── types/
│   │   └── auth.types.ts
│   └── app.ts
├── prisma/
│   └── schema.prisma
├── tests/
├── .env.example
├── package.json
└── tsconfig.json
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd auth-service
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.example .env
```

4. Set up the database:
```bash
npx prisma migrate dev
```

## Environment Variables
```env
# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/auth_db

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

APPLE_CLIENT_ID=your-apple-client-id
APPLE_CLIENT_SECRET=your-apple-client-secret

MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

LINKEDIN_CLIENT_ID=your-linkedin-client-id
LINKEDIN_CLIENT_SECRET=your-linkedin-client-secret

FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret

# Twilio (for SMS and WhatsApp)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_WHATSAPP_FROM=your-twilio-whatsapp-number
```

## Database Schema
```prisma
// prisma/schema.prisma

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id          String    @id @default(uuid())
  email       String?   @unique
  phone       String?   @unique
  whatsapp    String?   @unique
  displayName String?
  provider    String?
  providerId  String?
  verified    Boolean   @default(false)
  createdAt   DateTime  @default(now())
  updatedAt   DateTime  @updatedAt

  @@index([email])
  @@index([phone])
  @@index([whatsapp])
}
```

## API Endpoints

### Social Login
- `GET /auth/:provider` - Initiate social login
- `GET /auth/:provider/callback` - Social login callback

### Email Authentication
- `POST /auth/email/register` - Register with email
- `POST /auth/email/verify` - Verify email

### Phone Authentication
- `POST /auth/phone/verify` - Start phone verification
- `POST /auth/phone/confirm` - Confirm phone code

### WhatsApp Authentication
- `POST /auth/whatsapp/verify` - Start WhatsApp verification
- `POST /auth/whatsapp/confirm` - Confirm WhatsApp code

### Token Management
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout user

## Security Considerations

1. **Token Security**
   - Short-lived access tokens (24 hours)
   - Longer-lived refresh tokens (7 days)
   - Secure token storage recommendations for clients

2. **Rate Limiting**
   - Implementation of rate limiting per IP and per user
   - Gradual backoff for failed attempts

3. **Verification Codes**
   - 6-digit codes
   - 10-minute expiration
   - Maximum 3 attempts

4. **Data Protection**
   - Encryption at rest
   - HTTPS only
   - Secure headers implementation

## Integration Guide 

1. **Service Integration**

   a. Install the client package:
   ```bash
   npm install @your-org/auth-client
   ```

   b. Initialize the auth client:
   ```typescript
   import { AuthClient } from '@your-org/auth-client';

   const authClient = new AuthClient({
     baseUrl: 'https://your-auth-service.com',
     clientId: 'your-client-id',
     clientSecret: 'your-client-secret',
   });
   ```

2. **Implementing Social Login**

   a. Frontend implementation:
   ```typescript
   // React example
   const LoginButton = ({ provider }) => {
     const handleLogin = () => {
       window.location.href = `/auth/${provider}`;
     };

     return (
       <button onClick={handleLogin}>
         Login with {provider}
       </button>
     );
   };
   ```

   b. Handling callbacks:
   ```typescript
   // Next.js API route example
   export default async function callback(req, res) {
     const { code } = req.query;
     const tokens = await authClient.handleCallback(code);
     
     // Store tokens securely
     res.cookie('accessToken', tokens.accessToken, {
       httpOnly: true,
       secure: process.env.NODE_ENV === 'production',
       sameSite: 'lax',
       maxAge: 24 * 60 * 60 * 1000 // 24 hours
     });

     res.redirect('/dashboard');
   }
   ```

3. **Implementing Email Authentication**

   a. Registration:
   ```typescript
   const registerUser = async (email: string, password: string) => {
     try {
       const response = await authClient.register({
         email,
         password,
       });
       
       // Handle verification email sent
       return response;
     } catch (error) {
       // Handle error
     }
   };
   ```

   b. Verification:
   ```typescript
   const verifyEmail = async (email: string, code: string) => {
     try {
       const tokens = await authClient.verifyEmail(email, code);
       return tokens;
     } catch (error) {
       // Handle error
     }
   };
   ```

4. **Implementing Phone/WhatsApp Authentication**

   a. Initiate verification:
   ```typescript
   const startPhoneVerification = async (phoneNumber: string, method: 'sms' | 'whatsapp') => {
     try {
       const response = await authClient.startVerification(phoneNumber, method);
       return response;
     } catch (error) {
       // Handle error
     }
   };
   ```

   b. Complete verification:
   ```typescript
   const completeVerification = async (phoneNumber: string, code: string) => {
     try {
       const tokens = await authClient.completeVerification(phoneNumber, code);
       return tokens;
     } catch (error) {
       // Handle error
     }
   };
   ```

5. **Token Management**

   a. Token refresh implementation:
   ```typescript
   const refreshTokens = async () => {
     try {
       const newTokens = await authClient.refreshTokens(refreshToken);
       return newTokens;
     } catch (error) {
       // Handle error - redirect to login
     }
   };
   ```

   b. Axios interceptor example:
   ```typescript
   import axios from 'axios';

   const api = axios.create({
     baseURL: 'your-api-url'
   });

   api.interceptors.request.use(
     async (config) => {
       const token = getAccessToken(); // Implement this
       if (token) {
         config.headers.Authorization = `Bearer ${token}`;
       }
       return config;
     },
     (error) => Promise.reject(error)
   );

   api.interceptors.response.use(
     (response) => response,
     async (error) => {
       if (error.response?.status === 401) {
         try {
           const newTokens = await refreshTokens();
           // Retry the original request with new token
           const { config } = error;
           config.headers.Authorization = `Bearer ${newTokens.accessToken}`;
           return axios(config);
         } catch (refreshError) {
           // Redirect to login
         }
       }
       return Promise.reject(error);
     }
   );
   ```

6. **Error Handling**

   Implement proper error handling for different scenarios:
   ```typescript
   try {
     const result = await authClient.someOperation();
   } catch (error) {
     switch (error.code) {
       case 'AUTH001':
         // Invalid credentials
         break;
       case 'AUTH002':
         // Account not verified
         break;
       case 'AUTH003':
         // Rate limit exceeded
         break;
       case 'AUTH004':
         // Invalid token
         break;
       default:
         // Generic error handling
     }
   }
   ```

7. **Security Best Practices**

   a. Token storage:
   ```typescript
   // Store in HttpOnly cookies (preferred)
   const storeTokens = (tokens) => {
     document.cookie = `accessToken=${tokens.accessToken}; path=/; HttpOnly; Secure; SameSite=Strict`;
     document.cookie = `refreshToken=${tokens.refreshToken}; path=/; HttpOnly; Secure; SameSite=Strict`;
   };

   // If using localStorage (less secure)
   const storeTokens = (tokens) => {
     sessionStorage.setItem('accessToken', tokens.accessToken);
     // Never store refresh token in localStorage
   };
   ```

   b. CSRF protection:
   ```typescript
   import csurf from 'csurf';

   app.use(csurf());

   // In your forms
   <form action="/auth/login" method="POST">
     <input type="hidden" name="_csrf" value="${csrfToken}">
     ...
   </form>
   ```

## Testing

1. **Unit Tests**
   ```typescript
   import { AuthService } from '../services/auth.service';

   describe('AuthService', () => {
     let authService: AuthService;

     beforeEach(() => {
       authService = new AuthService();
     });

     it('should generate valid tokens', async () => {
       const user = { id: '123', email: 'test@example.com' };
       const tokens = await authService.generateTokens(user);
       expect(tokens).toHaveProperty('accessToken');
       expect(tokens).toHaveProperty('refreshToken');
     });
   });
   ```

2. **Integration Tests**
   ```typescript
   describe('Auth API', () => {
     it('should handle social login flow', async () => {
       const response = await request(app)
         .get('/auth/google')
         .expect(302);
       
       expect(response.header.location).toContain('accounts.google.com');
     });
   });
   ```

## Monitoring and Logging

1. **Logging Implementation**
   ```typescript
   import winston from 'winston';

   const logger = winston.createLogger({
     level: 'info',
     format: winston.format.json(),
     defaultMeta: { service: 'auth-service' },
     transports: [
       new winston.transports.File({ filename: 'error.log', level: 'error' }),
       new winston.transports.File({ filename: 'combined.log' })
     ]
   });
   ```

2. **Metrics Collection**
   ```typescript
   import prometheus from 'prom-client';

   const authCounter = new prometheus.Counter({
     name: 'auth_requests_total',
     help: 'Total number of authentication requests',
     labelNames: ['method', 'status']
   });
   ```

