import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, ArrowLeft, Save, 
  RefreshCw, User, Lock, Mail, Shield, 
  Bell, Clock, Check, X, AlertTriangle,
  CheckCircle, Key
} from 'lucide-react';

const Settings = ({ navigateTo, userData }) => {
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  
  const [notifications, setNotifications] = useState({
    email: true,
    browser: true,
    vulnerabilities: true,
    newScans: false,
    reports: true
  });
  
  const [scanSettings, setScanSettings] = useState({
    automaticScans: false,
    scanFrequency: 'weekly',
    deepScan: true,
    customPayloads: false
  });
  
  const [activeTab, setActiveTab] = useState('profile');
  const [saveAttempted, setSaveAttempted] = useState(false);
  
  useEffect(() => {
    // In a real app, we would fetch the user data from the API
    if (userData) {
      setFormData(prev => ({
        ...prev,
        name: userData.username || '',
        email: userData.email || ''
      }));
    }
  }, [userData]);
  
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleNotificationChange = (setting) => {
    setNotifications(prev => ({
      ...prev,
      [setting]: !prev[setting]
    }));
  };
  
  const handleScanSettingChange = (setting) => {
    setScanSettings(prev => ({
      ...prev,
      [setting]: !prev[setting]
    }));
  };
  
  const handleFrequencyChange = (e) => {
    setScanSettings(prev => ({
      ...prev,
      scanFrequency: e.target.value
    }));
  };
  
  const saveSettings = async () => {
    // Validate form fields
    if (activeTab === 'profile') {
      if (!formData.name || !formData.email) {
        setError('Name and email are required');
        return;
      }
      
      if (formData.newPassword && formData.newPassword !== formData.confirmPassword) {
        setError('Passwords do not match');
        return;
      }
    }
    
    setSaveAttempted(true);
    setLoading(true);
    setError(null);
    
    try {
      // In a real app, we would make an API call to save the settings
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError('Failed to save settings');
    } finally {
      setLoading(false);
    }
  };
  
  const isPasswordValid = () => {
    if (!formData.newPassword) return true;
    return formData.newPassword.length >= 8;
  };
  
  const passwordValidation = saveAttempted && formData.newPassword && !isPasswordValid();
  const passwordMismatch = saveAttempted && formData.newPassword && formData.newPassword !== formData.confirmPassword;
  
  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-6 flex items-center">
          <button
            onClick={() => navigateTo('dashboard')}
            className="mr-4 flex items-center text-gray-700 hover:text-blue-800"
          >
            <ArrowLeft size={16} className="mr-1" />
            Back
          </button>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <SettingsIcon size={24} className="mr-2 text-blue-800" />
            Settings
          </h1>
        </div>
        
        {success && (
          <div className="mb-6 bg-green-50 border border-green-200 text-green-800 rounded-md p-4 flex items-start">
            <CheckCircle size={18} className="text-green-600 mr-3 mt-0.5 flex-shrink-0" />
            <span>Settings saved successfully</span>
          </div>
        )}
        
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-800 rounded-md p-4 flex items-start">
            <AlertTriangle size={18} className="text-red-600 mr-3 mt-0.5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
        
        <div className="bg-white shadow-lg rounded-lg overflow-hidden">
          <div className="border-b border-gray-200">
            <nav className="flex">
              <button
                onClick={() => setActiveTab('profile')}
                className={`px-6 py-4 text-center border-b-2 font-medium text-sm ${
                  activeTab === 'profile'
                    ? 'border-blue-800 text-blue-800'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <User size={16} className="inline-block mr-2" />
                Profile
              </button>
              <button
                onClick={() => setActiveTab('notifications')}
                className={`px-6 py-4 text-center border-b-2 font-medium text-sm ${
                  activeTab === 'notifications'
                    ? 'border-blue-800 text-blue-800'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Bell size={16} className="inline-block mr-2" />
                Notifications
              </button>
              <button
                onClick={() => setActiveTab('scanSettings')}
                className={`px-6 py-4 text-center border-b-2 font-medium text-sm ${
                  activeTab === 'scanSettings'
                    ? 'border-blue-800 text-blue-800'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Shield size={16} className="inline-block mr-2" />
                Scan Settings
              </button>
            </nav>
          </div>
          
          <div className="p-6">
            {activeTab === 'profile' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Profile Information</h3>
                  <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
                    <div>
                      <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                        Username
                      </label>
                      <div className="mt-1 relative rounded-md shadow-sm">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <User size={16} className="text-gray-400" />
                        </div>
                        <input
                          type="text"
                          name="name"
                          id="name"
                          className="focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm border-gray-300 rounded-md"
                          placeholder="Your username"
                          value={formData.name}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    
                    <div>
                      <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                        Email Address
                      </label>
                      <div className="mt-1 relative rounded-md shadow-sm">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <Mail size={16} className="text-gray-400" />
                        </div>
                        <input
                          type="email"
                          name="email"
                          id="email"
                          className="focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm border-gray-300 rounded-md"
                          placeholder="you@example.com"
                          value={formData.email}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="pt-6 border-t border-gray-200">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Change Password</h3>
                  <div className="space-y-4">
                    <div>
                      <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-700">
                        Current Password
                      </label>
                      <div className="mt-1 relative rounded-md shadow-sm">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <Key size={16} className="text-gray-400" />
                        </div>
                        <input
                          type="password"
                          name="currentPassword"
                          id="currentPassword"
                          className="focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm border-gray-300 rounded-md"
                          placeholder="••••••••"
                          value={formData.currentPassword}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    
                    <div>
                      <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700">
                        New Password
                      </label>
                      <div className="mt-1 relative rounded-md shadow-sm">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <Lock size={16} className="text-gray-400" />
                        </div>
                        <input
                          type="password"
                          name="newPassword"
                          id="newPassword"
                          className={`focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm rounded-md ${
                            passwordValidation ? 'border-red-300' : 'border-gray-300'
                          }`}
                          placeholder="••••••••"
                          value={formData.newPassword}
                          onChange={handleInputChange}
                        />
                      </div>
                      {passwordValidation && (
                        <p className="mt-1 text-sm text-red-600">Password must be at least 8 characters</p>
                      )}
                    </div>
                    
                    <div>
                      <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                        Confirm New Password
                      </label>
                      <div className="mt-1 relative rounded-md shadow-sm">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <Lock size={16} className="text-gray-400" />
                        </div>
                        <input
                          type="password"
                          name="confirmPassword"
                          id="confirmPassword"
                          className={`focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm rounded-md ${
                            passwordMismatch ? 'border-red-300' : 'border-gray-300'
                          }`}
                          placeholder="••••••••"
                          value={formData.confirmPassword}
                          onChange={handleInputChange}
                        />
                      </div>
                      {passwordMismatch && (
                        <p className="mt-1 text-sm text-red-600">Passwords do not match</p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'notifications' && (
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">Notification Settings</h3>
                <p className="text-sm text-gray-500 mb-6">
                  Configure how you want to receive notifications about scan results and security alerts.
                </p>
                
                <div className="space-y-4">
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Email Notifications</h4>
                      <p className="text-xs text-gray-500">Receive notifications via email</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleNotificationChange('email')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        notifications.email ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          notifications.email ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Browser Notifications</h4>
                      <p className="text-xs text-gray-500">Show browser notifications</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleNotificationChange('browser')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        notifications.browser ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          notifications.browser ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Vulnerability Alerts</h4>
                      <p className="text-xs text-gray-500">Notify when vulnerabilities are found</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleNotificationChange('vulnerabilities')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        notifications.vulnerabilities ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          notifications.vulnerabilities ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">New Scan Notifications</h4>
                      <p className="text-xs text-gray-500">Notify when new scans are completed</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleNotificationChange('newScans')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        notifications.newScans ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          notifications.newScans ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Report Notifications</h4>
                      <p className="text-xs text-gray-500">Notify when new reports are available</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleNotificationChange('reports')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        notifications.reports ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          notifications.reports ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'scanSettings' && (
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">Scan Settings</h3>
                <p className="text-sm text-gray-500 mb-6">
                  Configure how the scanner operates when scanning your websites.
                </p>
                
                <div className="space-y-4">
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Automatic Scans</h4>
                      <p className="text-xs text-gray-500">Schedule regular scans of your websites</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleScanSettingChange('automaticScans')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        scanSettings.automaticScans ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          scanSettings.automaticScans ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  {scanSettings.automaticScans && (
                    <div className="ml-8 pt-2 pb-3">
                      <label htmlFor="scanFrequency" className="block text-sm font-medium text-gray-700 mb-2">
                        Scan Frequency
                      </label>
                      <select
                        id="scanFrequency"
                        name="scanFrequency"
                        className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
                        value={scanSettings.scanFrequency}
                        onChange={handleFrequencyChange}
                      >
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                      </select>
                    </div>
                  )}
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Deep Scanning</h4>
                      <p className="text-xs text-gray-500">Perform more thorough (but slower) security scans</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleScanSettingChange('deepScan')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        scanSettings.deepScan ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          scanSettings.deepScan ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                  
                  <div className="flex justify-between items-center py-3 border-b border-gray-200">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Custom SQL Payloads</h4>
                      <p className="text-xs text-gray-500">Use custom payloads for SQL injection testing</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleScanSettingChange('customPayloads')}
                      className={`relative inline-flex flex-shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                        scanSettings.customPayloads ? 'bg-blue-800' : 'bg-gray-200'
                      }`}
                    >
                      <span className="sr-only">Use setting</span>
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200 ${
                          scanSettings.customPayloads ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                </div>
                
                <div className="mt-6 bg-gray-50 p-4 rounded-md">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <Info size={18} className="h-5 w-5 text-blue-800" />
                    </div>
                    <div className="ml-3">
                      <h4 className="text-sm font-medium text-gray-900">About scan settings</h4>
                      <p className="text-xs text-gray-500 mt-1">
                        Deep scanning performs more thorough tests but may take longer. Custom SQL payloads allow you to test for specific vulnerabilities beyond the default set.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            <div className="mt-8 flex justify-end">
              <button
                type="button"
                onClick={saveSettings}
                disabled={loading}
                className={`flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white ${
                  loading ? 'bg-blue-400 cursor-not-allowed' : 'bg-blue-800 hover:bg-blue-700'
                } focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500`}
              >
                {loading ? (
                  <>
                    <RefreshCw size={16} className="mr-2 animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Save size={16} className="mr-2" />
                    Save Settings
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;