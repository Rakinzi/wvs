import React, { useState, useEffect } from 'react';
import { Camera, Shield, Lock, User, AlertTriangle, Eye, EyeOff } from 'lucide-react';

const Login = ({ onLogin, navigateTo }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formState, setFormState] = useState('idle');

  useEffect(() => {
    setFormState('active');
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!username || !password) {
      setError('Please enter both username and password');
      setFormState('error');
      setTimeout(() => setFormState('active'), 500);
      return;
    }
    
    setIsLoading(true);
    setError('');
    setFormState('submitting');
    
    try {
      const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('username', data.username);
        setFormState('success');
        setTimeout(() => onLogin({ username: data.username }), 800);
      } else {
        setError(data.error || 'Failed to login');
        setFormState('error');
        setTimeout(() => setFormState('active'), 500);
      }
    } catch (err) {
      setError('Failed to connect to server');
      setFormState('error');
      setTimeout(() => setFormState('active'), 500);
    } finally {
      setIsLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleRegisterClick = () => {
    navigateTo('register');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-900 via-blue-800 to-blue-700 overflow-hidden">
      <div className={`absolute inset-0 overflow-hidden ${formState === 'active' ? 'opacity-100' : 'opacity-0'} transition-opacity duration-1000`}>
        <div className="absolute top-0 left-0 w-full h-full">
          <div className="absolute top-10 left-10 w-6 h-6 bg-white rounded-full opacity-20 animate-ping" style={{ animationDuration: '3s' }}></div>
          <div className="absolute top-1/4 right-1/3 w-4 h-4 bg-white rounded-full opacity-10 animate-ping" style={{ animationDuration: '5s' }}></div>
          <div className="absolute bottom-1/3 left-1/4 w-8 h-8 bg-white rounded-full opacity-15 animate-ping" style={{ animationDuration: '7s' }}></div>
          <div className="absolute bottom-10 right-10 w-5 h-5 bg-white rounded-full opacity-20 animate-ping" style={{ animationDuration: '4s' }}></div>
        </div>
      </div>

      <div className={`relative w-full max-w-md transform transition-all duration-500 ease-in-out 
        ${formState === 'idle' ? 'opacity-0 translate-y-10' : 'opacity-100 translate-y-0'} 
        ${formState === 'submitting' ? 'scale-95' : ''} 
        ${formState === 'success' ? 'scale-105 opacity-0' : ''} 
        ${formState === 'error' ? 'translate-x-1 translate-y-1 translate-x-0 translate-y-0' : ''}`}>
        
        <div className="bg-white rounded-2xl shadow-2xl overflow-hidden">
          <div className="relative h-28 bg-blue-800 flex items-center justify-center">
            <div className="absolute inset-0 overflow-hidden">
              <div className="absolute -top-10 -left-10 w-40 h-40 bg-blue-600 rounded-full opacity-30"></div>
              <div className="absolute -bottom-10 -right-10 w-40 h-40 bg-blue-600 rounded-full opacity-30"></div>
            </div>
            
            <div className="relative flex flex-col items-center">
              <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center shadow-lg mb-2">
                <Shield size={28} className="text-blue-800" />
              </div>
              <h2 className="text-white text-xl font-bold">Web Vulnerability Scanner</h2>
            </div>
          </div>
          
          <div className="p-8">
            <h3 className="text-2xl font-bold text-gray-800 mb-6 text-center">Sign In</h3>
            
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-4">
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User size={18} className="text-blue-800" />
                  </div>
                  <input
                    type="text"
                    id="username"
                    className="pl-10 w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock size={18} className="text-blue-800" />
                  </div>
                  <input
                    type={showPassword ? "text" : "password"}
                    id="password"
                    className="pl-10 w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                    <button
                      type="button"
                      onClick={togglePasswordVisibility}
                      className="text-gray-400 hover:text-gray-600 focus:outline-none"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>
              </div>
              
              {error && (
                <div className="flex items-center text-red-500 text-sm p-2 bg-red-50 rounded-lg">
                  <AlertTriangle size={16} className="mr-2 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              
              <button
                type="submit"
                disabled={isLoading}
                className={`w-full py-3 px-4 rounded-lg font-bold text-white transition-all duration-300 
                ${isLoading 
                  ? 'bg-blue-400 cursor-not-allowed' 
                  : 'bg-blue-800 hover:bg-blue-700 shadow-lg hover:shadow-xl'}`}
              >
                {isLoading ? (
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-5 w-5 border-t-2 border-b-2 border-white mr-2"></div>
                    <span>Signing in...</span>
                  </div>
                ) : (
                  'Sign in'
                )}
              </button>
              
              <div className="flex items-center justify-center text-gray-600 text-sm">
                <span>Don't have an account?</span>
                <button
                  type="button"
                  onClick={handleRegisterClick}
                  className="ml-2 text-blue-800 font-medium hover:text-blue-600 focus:outline-none"
                >
                  Register now
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;