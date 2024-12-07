import { useState } from 'react';
import { 
  Mail, 
  Lock, 
  LogIn, 
  KeyRound, 
  ArrowLeft, 
  Send, 
  MessageSquare,
  Key
} from 'lucide-react';

// Custom Social Icons Components
const SocialIcons = {
  Google: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5.17 5.84l-4.35 4.35L8.47 7.84c-.39-.39-1.02-.39-1.41 0-.39.39-.39 1.02 0 1.41l4.35 4.35-4.35 4.35c-.39.39-.39 1.02 0 1.41.39.39 1.02.39 1.41 0l4.35-4.35 4.35 4.35c.39.39 1.02.39 1.41 0 .39-.39.39-1.02 0-1.41l-4.35-4.35 4.35-4.35c.39-.39.39-1.02 0-1.41-.39-.39-1.02-.39-1.41 0z" />
    </svg>
  ),
  Apple: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z" />
    </svg>
  ),
  GitHub: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.49.5.09.68-.22.68-.48 0-.24-.01-1.02-.01-1.86-2.78.6-3.37-1.18-3.37-1.18-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02.8-.22 1.65-.33 2.5-.33.85 0 1.7.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85l-.01 2.75c0 .26.18.58.69.48C19.13 20.17 22 16.42 22 12c0-5.52-4.48-10-10-10z" />
    </svg>
  ),
  LinkedIn: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M19 3a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h14m-.5 15.5v-5.3a3.26 3.26 0 00-3.26-3.26c-.85 0-1.84.52-2.32 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 011.4 1.4v4.93h2.79M6.88 8.56a1.68 1.68 0 001.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 00-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z" />
    </svg>
  ),
  Microsoft: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M2 2h9v9H2V2zm11 0h9v9h-9V2zM2 13h9v9H2v-9zm11 0h9v9h-9v-9z" />
    </svg>
  ),
  Facebook: () => (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
      <path d="M20 3H4a1 1 0 00-1 1v16a1 1 0 001 1h8.62v-7h-2.35v-2.69h2.35v-2a3.27 3.27 0 013.49-3.59c.99.01 1.85.07 2.1.1v2.44h-1.44c-1.13 0-1.35.54-1.35 1.32v1.73h2.69L17.76 14h-2.34v7H20a1 1 0 001-1V4a1 1 0 00-1-1z" />
    </svg>
  )
};

function SocialIconButton({ platform }) {
  const Icon = SocialIcons[platform];
  return (
    <button 
      className="p-3 rounded-full border border-gray-200 hover:border-blue-500 hover:text-blue-600 transition-all duration-200 group bg-white"
      aria-label={`Sign in with ${platform}`}
    >
      <Icon />
    </button>
  );
}

export default function AuthUI() {
  const [mode, setMode] = useState('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-lg">
        <LoginForm setMode={setMode} />
      </div>
    </div>
  );
}

function LoginForm({ setMode }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  return (
    <div>
      <div className="text-center">
        <LogIn className="mx-auto h-12 w-12 text-blue-600" />
        <h2 className="mt-6 text-3xl font-bold text-gray-900">Welcome back</h2>
        <p className="mt-2 text-sm text-gray-600">Sign in to your account</p>
      </div>
      
      <div className="mt-8">
        {/* Quick Sign In Options */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <QuickSignInButton
            icon={<Send className="h-6 w-6" />}
            label="Magic Link"
            onClick={() => setMode('magic-link')}
          />
          <QuickSignInButton
            icon={<MessageSquare className="h-6 w-6" />}
            label="WhatsApp"
            onClick={() => setMode('whatsapp')}
          />
          <QuickSignInButton
            icon={<Key className="h-6 w-6" />}
            label="OTP"
            onClick={() => setMode('otp')}
          />
        </div>

        <div className="relative mb-8">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-200"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-white text-gray-500">or continue with email</span>
          </div>
        </div>

        <form className="space-y-6">
          <div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Mail className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg bg-gray-50 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Email address"
              />
            </div>
          </div>
          
          <div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg bg-gray-50 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Password"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-200"
            >
              Sign in
            </button>
          </div>
        </form>

        <div className="mt-8">
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-200"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-white text-gray-500">or continue with</span>
            </div>
          </div>

          <div className="mt-6">
            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-3 flex justify-center space-x-4">
                <SocialIconButton platform="Google" />
                <SocialIconButton platform="Apple" />
                <SocialIconButton platform="GitHub" />
                <SocialIconButton platform="LinkedIn" />
              </div>
              <div className="col-span-3 flex justify-center space-x-4">
                <SocialIconButton platform="Microsoft" />
                <SocialIconButton platform="Facebook" />
              </div>
            </div>
          </div>
        </div>

        <div className="mt-6 text-center text-sm">
          <span className="text-gray-600">Don't have an account?</span>
          {' '}
          <button
            onClick={() => setMode('register')}
            className="font-medium text-blue-600 hover:text-blue-500 transition-colors duration-200"
          >
            Sign up
          </button>
        </div>
      </div>
    </div>
  );
}

function QuickSignInButton({ icon, label, onClick }) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center justify-center p-4 border border-gray-200 rounded-xl hover:border-blue-500 hover:text-blue-600 transition-all duration-200 group bg-white"
    >
      <div className="text-gray-500 group-hover:text-blue-600 transition-colors duration-200">
        {icon}
      </div>
      <span className="mt-2 text-xs font-medium text-gray-600 group-hover:text-blue-600 transition-colors duration-200">
        {label}
      </span>
    </button>
  );
}
