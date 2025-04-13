import React, { useState, useEffect } from 'react';
import { Shield, Lock, User, Mail, AlertTriangle, Eye, EyeOff, CheckCircle, ArrowLeft } from 'lucide-react';

const Register = ({ navigateTo }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formState, setFormState] = useState('idle');
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    document.title = 'Register - Web Vulnerability Scanner';
    setFormState('active');
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear specific error when user types
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 4) {
      newErrors.username = 'Username must be at least 4 characters';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid';
    }
    
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }
    
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }
    
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const validationErrors = validateForm();
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      setFormState('error');
      setTimeout(() => setFormState('active'), 500);
      return;
    }
    
    setIsLoading(true);
    setFormState('submitting');
    
    try {
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          password: formData.password
        })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setSuccessMessage('Registration successful! You can now log in.');
        setFormState('success');
        setTimeout(() => navigateTo('login'), 2000);
      } else {
        setErrors({ form: data.error || 'Registration failed' });
        setFormState('error');
        setTimeout(() => setFormState('active'), 500);
      }
    } catch (err) {
      setErrors({ form: 'Failed to connect to server' });
      setFormState('error');
      setTimeout(() => setFormState('active'), 500);
    } finally {
      setIsLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleBackToLogin = () => {
    navigateTo('login');
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
        ${formState === 'success' ? 'scale-105' : ''} 
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
            <div className="flex items-center mb-6">
              <button 
                onClick={handleBackToLogin}
                className="flex items-center text-blue-800 hover:text-blue-600 transition-colors"
              >
                <ArrowLeft size={16} className="mr-1" />
                <span>Back to login</span>
              </button>
              <h3 className="text-2xl font-bold text-gray-800 text-center flex-1">Create Account</h3>
            </div>
            
            {formState === 'success' ? (
              <div className="bg-green-50 text-green-800 p-4 rounded-lg flex items-start">
                <CheckCircle size={20} className="mr-2 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-medium">{successMessage}</p>
                  <p className="text-sm mt-1">Redirecting to login page...</p>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5">
                <div className="space-y-4">
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <User size={18} className="text-blue-800" />
                    </div>
                    <input
                      type="text"
                      id="username"
                      name="username"
                      className={`pl-10 w-full px-4 py-3 rounded-lg border ${errors.username ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200`}
                      placeholder="Username"
                      value={formData.username}
                      onChange={handleChange}
                    />
                  </div>
                  {errors.username && (
                    <p className="text-red-500 text-xs pl-2">{errors.username}</p>
                  )}
                  
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Mail size={18} className="text-blue-800" />
                    </div>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      className={`pl-10 w-full px-4 py-3 rounded-lg border ${errors.email ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200`}
                      placeholder="Email address"
                      value={formData.email}
                      onChange={handleChange}
                    />
                  </div>
                  {errors.email && (
                    <p className="text-red-500 text-xs pl-2">{errors.email}</p>
                  )}
                  
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock size={18} className="text-blue-800" />
                    </div>
                    <input
                      type={showPassword ? "text" : "password"}
                      id="password"
                      name="password"
                      className={`pl-10 w-full px-4 py-3 rounded-lg border ${errors.password ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200`}
                      placeholder="Password"
                      value={formData.password}
                      onChange={handleChange}
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
                  {errors.password && (
                    <p className="text-red-500 text-xs pl-2">{errors.password}</p>
                  )}
                  
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock size={18} className="text-blue-800" />
                    </div>
                    <input
                      type={showPassword ? "text" : "password"}
                      id="confirmPassword"
                      name="confirmPassword"
                      className={`pl-10 w-full px-4 py-3 rounded-lg border ${errors.confirmPassword ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200`}
                      placeholder="Confirm password"
                      value={formData.confirmPassword}
                      onChange={handleChange}
                    />
                  </div>
                  {errors.confirmPassword && (
                    <p className="text-red-500 text-xs pl-2">{errors.confirmPassword}</p>
                  )}
                </div>
                
                {errors.form && (
                  <div className="flex items-center text-red-500 text-sm p-2 bg-red-50 rounded-lg">
                    <AlertTriangle size={16} className="mr-2 flex-shrink-0" />
                    <span>{errors.form}</span>
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
                      <span>Creating account...</span>
                    </div>
                  ) : (
                    'Register'
                  )}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;