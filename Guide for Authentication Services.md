I'll help you create a comprehensive guide and implementation for the authentication system across multiple platforms. Let's break this down systematically.





# Multi-Platform Authentication System

## System Overview
A complete authentication system with support for:
- Multiple authentication methods (email/password, social, magic link, WhatsApp)
- Multi-factor authentication (MFA)
- Cross-platform support (Web, Mobile, API)
- Session management
- Security features

## Architecture Components

### 1. Backend (Python/FastAPI)
- RESTful API service
- JWT token management
- Database management
- Social auth integration
- MFA implementation
- Security middleware

### 2. Frontend (React)
- Authentication UI
- Session management
- Protected routes
- MFA integration
- Social login integration

### 3. Mobile (Flutter)
- Native authentication UI
- Biometric authentication
- Secure storage
- MFA support
- Deep linking

### 4. Infrastructure
- AWS deployment
- Docker containerization
- CI/CD pipeline
- Monitoring and logging

## Security Features
- JWT with refresh tokens
- Rate limiting
- CORS protection
- Password hashing
- Session management
- MFA (TOTP, SMS, Email)
- Audit logging

## Data Flow
1. User initiates authentication
2. Backend validates credentials
3. MFA verification (if enabled)
4. Token generation and session creation
5. Client-side session management
6. Secure storage of credentials

## API Endpoints
```
POST /auth/register
POST /auth/login
POST /auth/refresh
POST /auth/logout
POST /auth/mfa/enable
POST /auth/mfa/verify
POST /auth/social/{provider}
POST /auth/magic-link
POST /auth/whatsapp
```


Let me create the backend implementation first:

```python
# app/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional
import jwt
import pyotp
import uuid

from .database import get_db
from .models import User, MFADevice
from .schemas import UserCreate, UserLogin, TokenResponse
from .config import Settings

app = FastAPI()
settings = Settings()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Authentication routes
@app.post("/auth/register", response_model=TokenResponse)
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        id=str(uuid.uuid4())
    )
    db.add(user)
    db.commit()
    
    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@app.post("/auth/login", response_model=TokenResponse)
async def login_user(user_data: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )
    
    # Check if MFA is enabled
    mfa_device = db.query(MFADevice).filter(MFADevice.user_id == user.id).first()
    if mfa_device:
        return TokenResponse(
            access_token=None,
            refresh_token=None,
            mfa_required=True,
            mfa_token=create_mfa_token(user.id)
        )
    
    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@app.post("/auth/mfa/enable")
async def enable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Generate TOTP secret
    secret = pyotp.random_base32()
    
    # Create MFA device
    mfa_device = MFADevice(
        user_id=current_user.id,
        secret=secret,
        is_active=True
    )
    db.add(mfa_device)
    db.commit()
    
    # Generate QR code URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        current_user.email,
        issuer_name="YourApp"
    )
    
    return {
        "secret": secret,
        "qr_code_uri": provisioning_uri
    }

@app.post("/auth/mfa/verify")
async def verify_mfa(
    token: str,
    code: str,
    db: Session = Depends(get_db)
):
    # Verify MFA token
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid MFA token")
    
    # Get user's MFA device
    mfa_device = db.query(MFADevice).filter(
        MFADevice.user_id == user_id,
        MFADevice.is_active == True
    ).first()
    
    if not mfa_device:
        raise HTTPException(status_code=400, detail="MFA not enabled")
    
    # Verify TOTP code
    totp = pyotp.TOTP(mfa_device.secret)
    if not totp.verify(code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    
    # Generate tokens
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

# Utility functions
def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

def create_mfa_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=5),
        "type": "mfa"
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

# Database models (models.py)
from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    mfa_devices = relationship("MFADevice", back_populates="user")

class MFADevice(Base):
    __tablename__ = "mfa_devices"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    secret = Column(String)
    is_active = Column(Boolean, default=True)
    user = relationship("User", back_populates="mfa_devices")

```

Now, let's create the React frontend implementation:

```typescript
// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../services/api';

interface AuthContextData {
  user: User | null;
  signIn: (credentials: SignInCredentials) => Promise<void>;
  signOut: () => void;
  verifyMfa: (code: string) => Promise<void>;
  enableMfa: () => Promise<{ secret: string; qrCodeUri: string }>;
}

const AuthContext = createContext<AuthContextData>({} as AuthContextData);

export const AuthProvider: React.FC = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  useEffect(() => {
    // Load saved user
    const storedUser = localStorage.getItem('@Auth:user');
    const storedToken = localStorage.getItem('@Auth:token');

    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
      api.defaults.headers.authorization = `Bearer ${storedToken}`;
    }
  }, []);

  const signIn = async ({ email, password }: SignInCredentials) => {
    const response = await api.post('/auth/login', {
      email,
      password,
    });

    if (response.data.mfa_required) {
      setMfaToken(response.data.mfa_token);
      throw new Error('MFA_REQUIRED');
    }

    const { user, token } = response.data;

    localStorage.setItem('@Auth:user', JSON.stringify(user));
    localStorage.setItem('@Auth:token', token);

    api.defaults.headers.authorization = `Bearer ${token}`;

    setUser(user);
  };

  const verifyMfa = async (code: string) => {
    if (!mfaToken) throw new Error('No MFA token');

    const response = await api.post('/auth/mfa/verify', {
      token: mfaToken,
      code,
    });

    const { user, token } = response.data;

    localStorage.setItem('@Auth:user', JSON.stringify(user));
    localStorage.setItem('@Auth:token', token);

    api.defaults.headers.authorization = `Bearer ${token}`;

    setUser(user);
    setMfaToken(null);
  };

  const enableMfa = async () => {
    const response = await api.post('/auth/mfa/enable');
    return response.data;
  };

  const signOut = () => {
    localStorage.removeItem('@Auth:user');
    localStorage.removeItem('@Auth:token');
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, signIn, signOut, verifyMfa, enableMfa }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};

```

Now for the Flutter mobile implementation:

```dart
// lib/services/auth_service.dart
import 'package:flutter_secure_storage/flutter_secure_storage';
import 'package:local_auth/local_auth.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;

class AuthService {
  final storage = FlutterSecureStorage();
  final localAuth = LocalAuthentication();
  final String baseUrl = 'https://your-api.com';

  Future<Map<String, dynamic>> signIn(String email, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/auth/login'),
      body: json.encode({
        'email': email,
        'password': password,
      }),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      if (data['mfa_required'] == true) {
        await storage.write(key: 'mfa_token', value: data['mfa_token']);
        throw AuthException('MFA_REQUIRED');
      }

      await _saveAuthData(data);
      return data;
    }

    throw AuthException('Invalid credentials');
  }

  Future<bool> verifyMfa(String code) async {
    final mfaToken = await storage.read(key: 'mfa_token');
    if (mfaToken == null) throw AuthException('No MFA token');

    final response = await http.post(
      Uri.parse('$baseUrl/auth/mfa/verify'),
      body: json.encode({
        'token': mfaToken,
        'code': code,
      }),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      await _saveAuthData(data);
      await storage.delete(key: 'mfa_token');
      return true;
    }

    return false;
  }

  Future<Map<String, String>> enableMfa() async {
    final token = await storage.read(key: 'access_token');
    final response = await http.post(
      Uri.parse('$baseUrl/auth/mfa/enable'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token',
      },
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      return {
        'secret': data['secret'],
        'qrCodeUri': data['qr_code_uri'],
      };
    }

    throw AuthException('Failed to enable MFA');
  }

  Future<bool> checkBiometrics() async {
    try {
      return await localAuth.canCheckBiometrics;
    } catch (e) {
      return false;
    }
  }

  Future<bool> authenticateWithBiometrics() async {
    try {
      return await localAuth.authenticate(
        localizedReason: 'Authenticate to access the app',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } catch (e) {
      return false;
    }
  }

  Future<void> _saveAuthData(Map<String, dynamic> data) async {
    await storage.write(key: 'access_token', value: data['access_token']);
    await
```
