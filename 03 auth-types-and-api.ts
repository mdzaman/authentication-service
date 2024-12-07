// src/types/auth.types.ts
export type AuthMode = 'login' | 'register' | 'reset' | 'magic-link' | 'whatsapp';

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: UserData;
}

export interface UserData {
  id: string;
  email?: string;
  phone?: string;
  whatsapp?: string;
  name?: string;
  verified: boolean;
}

export interface AuthError {
  message: string;
  code: string;
}

// src/services/api.ts
import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const authApi = {
  login: async (email: string, password: string) => {
    const response = await api.post('/auth/login', { email, password });
    return response.data;
  },

  register: async (data: { email: string; password: string; name: string }) => {
    const response = await api.post('/auth/register', data);
    return response.data;
  },

  resetPassword: async (email: string) => {
    const response = await api.post('/auth/reset-password', { email });
    return response.data;
  },

  sendMagicLink: async (email: string) => {
    const response = await api.post('/auth/magic-link', { email });
    return response.data;
  },

  verifyMagicLink: async (token: string) => {
    const response = await api.post('/auth/verify-magic-link', { token });
    return response.data;
  },

  sendWhatsAppCode: async (whatsapp: string) => {
    const response = await api.post('/auth/whatsapp/send-code', { whatsapp });
    return response.data;
  },

  verifyWhatsAppCode: async (whatsapp: string, code: string) => {
    const response = await api.post('/auth/whatsapp/verify-code', { whatsapp, code });
    return response.data;
  },

  socialAuth: async (provider: string) => {
    window.location.href = `${api.defaults.baseURL}/auth/${provider}`;
  },
};
