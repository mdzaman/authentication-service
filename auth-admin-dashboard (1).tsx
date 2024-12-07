import { useState } from 'react';
import { Settings, Users, Key, Shield, Bell, Database, Lock } from 'lucide-react';

export default function AuthDashboard() {
  const [activeTab, setActiveTab] = useState('providers');
  
  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <div className="w-64 bg-white shadow-md">
        <div className="p-4 border-b">
          <h1 className="text-xl font-semibold">Auth Admin</h1>
        </div>
        <nav className="p-4">
          <button 
            onClick={() => setActiveTab('providers')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'providers' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Key className="w-5 h-5 mr-3" />
            Providers
          </button>
          <button 
            onClick={() => setActiveTab('users')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'users' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Users className="w-5 h-5 mr-3" />
            Users
          </button>
          <button 
            onClick={() => setActiveTab('security')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'security' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Shield className="w-5 h-5 mr-3" />
            Security
          </button>
          <button 
            onClick={() => setActiveTab('notifications')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'notifications' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Bell className="w-5 h-5 mr-3" />
            Notifications
          </button>
          <button 
            onClick={() => setActiveTab('database')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'database' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Database className="w-5 h-5 mr-3" />
            Database
          </button>
          <button 
            onClick={() => setActiveTab('settings')}
            className={`flex items-center w-full p-2 rounded mb-2 ${activeTab === 'settings' ? 'bg-blue-50 text-blue-600' : 'hover:bg-gray-50'}`}
          >
            <Settings className="w-5 h-5 mr-3" />
            Settings
          </button>
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="p-8">
          {activeTab === 'providers' && <ProvidersPanel />}
          {activeTab === 'users' && <UsersPanel />}
          {activeTab === 'security' && <SecurityPanel />}
          {activeTab === 'notifications' && <NotificationsPanel />}
          {activeTab === 'database' && <DatabasePanel />}
          {activeTab === 'settings' && <SettingsPanel />}
        </div>
      </div>
    </div>
  );
}

function ProvidersPanel() {
  const [providers, setProviders] = useState({
    google: true,
    apple: false,
    microsoft: true,
    github: true,
    linkedin: false,
    facebook: true
  });

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Authentication Providers</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(providers).map(([provider, enabled]) => (
          <div key={provider} className="bg-white p-6 rounded-lg shadow">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-medium capitalize">{provider}</h3>
              <button 
                onClick={() => setProviders(prev => ({ ...prev, [provider]: !prev[provider] }))}
                className={`px-4 py-2 rounded ${enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}
              >
                {enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>
            <div className="space-y-4">
              <input 
                type="text" 
                placeholder="Client ID"
                className="w-full p-2 border rounded"
              />
              <input 
                type="password" 
                placeholder="Client Secret"
                className="w-full p-2 border rounded"
              />
              <input 
                type="text" 
                placeholder="Redirect URI"
                className="w-full p-2 border rounded"
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function UsersPanel() {
  const [users] = useState([
    { id: 1, name: 'John Doe', email: 'john@example.com', provider: 'google', status: 'active' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com', provider: 'email', status: 'pending' },
    { id: 3, name: 'Bob Wilson', email: 'bob@example.com', provider: 'github', status: 'active' },
  ]);

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">User Management</h2>
      <div className="bg-white rounded-lg shadow">
        <table className="min-w-full">
          <thead>
            <tr className="border-b">
              <th className="px-6 py-3 text-left">Name</th>
              <th className="px-6 py-3 text-left">Email</th>
              <th className="px-6 py-3 text-left">Provider</th>
              <th className="px-6 py-3 text-left">Status</th>
              <th className="px-6 py-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className="border-b">
                <td className="px-6 py-4">{user.name}</td>
                <td className="px-6 py-4">{user.email}</td>
                <td className="px-6 py-4 capitalize">{user.provider}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-sm ${
                    user.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {user.status}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <button className="text-blue-600 hover:text-blue-800">Edit</button>
                  <button className="text-red-600 hover:text-red-800 ml-4">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SecurityPanel() {
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Security Settings</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium mb-4">Password Policy</h3>
          <div className="space-y-4">
            <div>
              <label className="block mb-2">Minimum Length</label>
              <input type="number" className="w-full p-2 border rounded" defaultValue={8} />
            </div>
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" defaultChecked />
              <label>Require uppercase letters</label>
            </div>
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" defaultChecked />
              <label>Require numbers</label>
            </div>
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" defaultChecked />
              <label>Require special characters</label>
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium mb-4">Two-Factor Authentication</h3>
          <div className="space-y-4">
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" />
              <label>Require 2FA for all users</label>
            </div>
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" defaultChecked />
              <label>Allow SMS verification</label>
            </div>
            <div className="flex items-center">
              <input type="checkbox" className="mr-2" defaultChecked />
              <label>Allow authenticator apps</label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function NotificationsPanel() {
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Notification Settings</h2>
      <div className="bg-white p-6 rounded-lg shadow">
        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-medium mb-4">Email Templates</h3>
            <div className="space-y-4">
              <div>
                <label className="block mb-2">Welcome Email</label>
                <textarea className="w-full p-2 border rounded h-32" />
              </div>
              <div>
                <label className="block mb-2">Password Reset</label>
                <textarea className="w-full p-2 border rounded h-32" />
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-lg font-medium mb-4">SMS Templates</h3>
            <div className="space-y-4">
              <div>
                <label className="block mb-2">Verification Code</label>
                <textarea className="w-full p-2 border rounded h-32" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function DatabasePanel() {
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Database Configuration</h2>
      <div className="bg-white p-6 rounded-lg shadow">
        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-medium mb-4">Connection Settings</h3>
            <div className="space-y-4">
              <div>
                <label className="block mb-2">Database URL</label>
                <input type="text" className="w-full p-2 border rounded" />
              </div>
              <div>
                <label className="block mb-2">Username</label>
                <input type="text" className="w-full p-2 border rounded" />
              </div>
              <div>
                <label className="block mb-2">Password</label>
                <input type="password" className="w-full p-2 border rounded" />
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-lg font-medium mb-4">Backup Settings</h3>
            <div className="space-y-4">
              <div className="flex items-center">
                <input type="checkbox" className="mr-2" defaultChecked />
                <label>Enable automatic backups</label>
              </div>
              <div>
                <label className="block mb-2">Backup Frequency (hours)</label>
                <input type="number" className="w-full p-2 border rounded" defaultValue={24} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsPanel() {
  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">General Settings</h2>
      <div className="bg-white p-6 rounded-lg shadow">
        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-medium mb-4">Service Configuration</h3>
            <div className="space-y-4">
              <div>
                <label className="block mb-2">Service Name</label>
                <input type="text" className="w-full p-2 border rounded" defaultValue="Authentication Service" />
              </div>
              <div>
                <label className="block mb-2">Base URL</label>
                <input type="text" className="w-full p-2 border rounded" defaultValue="https://auth.example.com" />
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-lg font-medium mb-4">Token Settings</h3>
            <div className="space-y-4">
              <div>
                <label className="block mb-2">Access Token Expiry (minutes)</label>
                <input type="number" className="w-full p-2 border rounded" defaultValue={60} />
              </div>
              <div>
                <label className="block mb-2">Refresh Token Expiry (days)</label>
                <input type="number" className="w-full p-2 border rounded" defaultValue={7} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
