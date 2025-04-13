import React, { useState, useEffect } from 'react';
import { 
  Shield, Menu, X, User, BarChart2, Clock, Settings, 
  LogOut, AlertTriangle, Bell, ChevronDown, Globe
} from 'lucide-react';

const Navbar = ({ isAuthenticated, onLogout, navigateTo, currentPage }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [animateNavbar, setAnimateNavbar] = useState(false);

  useEffect(() => {
    setAnimateNavbar(true);
    
    // Sample notifications - in real app these would come from an API
    setNotifications([
      { id: 1, type: 'alert', message: 'New vulnerability detected', time: '10 min ago' },
      { id: 2, type: 'info', message: 'System updated successfully', time: '1 hour ago' }
    ]);
  }, []);

  const toggleMobileMenu = () => {
    setMobileMenuOpen(!mobileMenuOpen);
  };

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  return (
    <nav className={`bg-blue-800 shadow-lg transition-all duration-500 ${animateNavbar ? 'opacity-100' : 'opacity-0'}`}>
      <div className="max-w-7xl mx-auto px-2 sm:px-4 lg:px-8">
        <div className="relative flex items-center justify-between h-16">
          {/* Logo section */}
          <div className="flex items-center">
            <div className="flex-shrink-0 flex items-center">
              <div className="bg-white p-1 rounded-md shadow-sm mr-2">
                <Shield size={20} className="text-blue-800" />
              </div>
              <span 
                className="text-white text-xl font-bold cursor-pointer"
                onClick={() => isAuthenticated && navigateTo('dashboard')}
              >
                WebVulnScanner
              </span>
            </div>
            
            {isAuthenticated && (
              <div className="hidden md:ml-6 md:flex md:space-x-2">
                <button
                  onClick={() => navigateTo('dashboard')}
                  className={`${
                    currentPage === 'dashboard'
                      ? 'bg-blue-900 text-white'
                      : 'text-blue-200 hover:bg-blue-700 hover:text-white'
                  } px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center`}
                >
                  <BarChart2 size={16} className="mr-1" />
                  Dashboard
                </button>
                
                <button
                  onClick={() => navigateTo('history')}
                  className={`${
                    currentPage === 'history'
                      ? 'bg-blue-900 text-white'
                      : 'text-blue-200 hover:bg-blue-700 hover:text-white'
                  } px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center`}
                >
                  <Clock size={16} className="mr-1" />
                  Scan History
                </button>
                
                <button
                  onClick={() => navigateTo('blockedSites')}
                  className={`${
                    currentPage === 'blockedSites'
                      ? 'bg-blue-900 text-white'
                      : 'text-blue-200 hover:bg-blue-700 hover:text-white'
                  } px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center`}
                >
                  <AlertTriangle size={16} className="mr-1" />
                  Blocked Sites
                </button>
                
                <button
                  onClick={() => navigateTo('blockedAccess')}
                  className={`${
                    currentPage === 'blockedAccess'
                      ? 'bg-blue-900 text-white'
                      : 'text-blue-200 hover:bg-blue-700 hover:text-white'
                  } px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center`}
                >
                  <Globe size={16} className="mr-1" />
                  Access Attempts
                </button>
              </div>
            )}
          </div>
          
          {/* Right section */}
          {isAuthenticated ? (
            <div className="flex items-center">
              {/* Notifications dropdown */}
              <div className="relative mr-3">
                <button
                  className="relative p-1 rounded-full text-blue-200 hover:text-white focus:outline-none"
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                >
                  <Bell size={20} />
                  {notifications.length > 0 && (
                    <span className="absolute top-0 right-0 -mt-1 -mr-1 px-1.5 py-0.5 text-xs leading-none bg-red-500 text-white rounded-full">
                      {notifications.length}
                    </span>
                  )}
                </button>
                
                {dropdownOpen && (
                  <div className="origin-top-right absolute right-0 mt-2 w-80 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
                    <div className="py-1">
                      <div className="px-4 py-3 border-b border-gray-200">
                        <h3 className="text-sm font-medium text-gray-700">Notifications</h3>
                      </div>
                      {notifications.length > 0 ? (
                        <div>
                          {notifications.map(notification => (
                            <div key={notification.id} className="px-4 py-3 hover:bg-gray-50 border-b border-gray-100">
                              <div className="flex items-start">
                                <div className={`flex-shrink-0 rounded-full p-1 ${
                                  notification.type === 'alert' ? 'bg-red-100 text-red-600' : 'bg-blue-100 text-blue-600'
                                }`}>
                                  {notification.type === 'alert' ? <AlertTriangle size={16} /> : <Bell size={16} />}
                                </div>
                                <div className="ml-3 w-0 flex-1">
                                  <p className="text-sm font-medium text-gray-900">{notification.message}</p>
                                  <p className="mt-1 text-xs text-gray-500">{notification.time}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                          <div className="px-4 py-2 text-center">
                            <button className="text-xs text-blue-800 font-medium">View all notifications</button>
                          </div>
                        </div>
                      ) : (
                        <div className="px-4 py-6 text-center">
                          <p className="text-sm text-gray-600">No new notifications</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
              
              {/* User menu */}
              <div className="hidden sm:ml-3 sm:flex sm:items-center">
                <div className="relative">
                  <button
                    onClick={toggleDropdown}
                    className="flex items-center space-x-2 text-blue-200 hover:text-white focus:outline-none"
                  >
                    <div className="h-8 w-8 rounded-full bg-blue-900 flex items-center justify-center">
                      <User size={16} className="text-blue-200" />
                    </div>
                    <ChevronDown size={16} className={`transition-transform duration-200 ${dropdownOpen ? 'transform rotate-180' : ''}`} />
                  </button>
                  
                  {dropdownOpen && (
                    <div className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
                      <div className="py-1">
                        <button
                          onClick={() => {
                            setDropdownOpen(false);
                            navigateTo('settings');
                          }}
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                        >
                          <Settings size={16} className="mr-2 text-gray-500" />
                          Settings
                        </button>
                        <button
                          onClick={() => {
                            setDropdownOpen(false);
                            onLogout();
                          }}
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                        >
                          <LogOut size={16} className="mr-2 text-gray-500" />
                          Logout
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              {/* Mobile menu button */}
              <div className="flex items-center sm:hidden">
                <button
                  onClick={toggleMobileMenu}
                  className="inline-flex items-center justify-center p-2 rounded-md text-blue-200 hover:text-white hover:bg-blue-700 focus:outline-none"
                >
                  {mobileMenuOpen ? (
                    <X size={24} />
                  ) : (
                    <Menu size={24} />
                  )}
                </button>
              </div>
            </div>
          ) : (
            <div className="flex items-center">
              <button
                onClick={() => navigateTo('login')}
                className="bg-white px-4 py-2 rounded-md text-sm font-medium text-blue-800 hover:bg-blue-50 transition-colors duration-200 shadow-sm flex items-center"
              >
                <User size={16} className="mr-1" />
                Login
              </button>
            </div>
          )}
        </div>
      </div>
      
      {/* Mobile menu */}
      {isAuthenticated && mobileMenuOpen && (
        <div className="md:hidden">
          <div className="pt-2 pb-3 space-y-1">
            <button
              onClick={() => {
                navigateTo('dashboard');
                setMobileMenuOpen(false);
              }}
              className={`${
                currentPage === 'dashboard'
                  ? 'bg-blue-900 text-white'
                  : 'text-blue-200 hover:bg-blue-700 hover:text-white'
              } flex items-center w-full px-3 py-2 text-base font-medium`}
            >
              <BarChart2 size={16} className="mr-2" />
              Dashboard
            </button>
            
            <button
              onClick={() => {
                navigateTo('history');
                setMobileMenuOpen(false);
              }}
              className={`${
                currentPage === 'history'
                  ? 'bg-blue-900 text-white'
                  : 'text-blue-200 hover:bg-blue-700 hover:text-white'
              } flex items-center w-full px-3 py-2 text-base font-medium`}
            >
              <Clock size={16} className="mr-2" />
              Scan History
            </button>
            
            <button
              onClick={() => {
                navigateTo('blockedSites');
                setMobileMenuOpen(false);
              }}
              className={`${
                currentPage === 'blockedSites'
                  ? 'bg-blue-900 text-white'
                  : 'text-blue-200 hover:bg-blue-700 hover:text-white'
              } flex items-center w-full px-3 py-2 text-base font-medium`}
            >
              <AlertTriangle size={16} className="mr-2" />
              Blocked Sites
            </button>
            
            <button
              onClick={() => {
                navigateTo('blockedAccess');
                setMobileMenuOpen(false);
              }}
              className={`${
                currentPage === 'blockedAccess'
                  ? 'bg-blue-900 text-white'
                  : 'text-blue-200 hover:bg-blue-700 hover:text-white'
              } flex items-center w-full px-3 py-2 text-base font-medium`}
            >
              <Globe size={16} className="mr-2" />
              Access Attempts
            </button>
            
            <button
              onClick={() => {
                navigateTo('settings');
                setMobileMenuOpen(false);
              }}
              className={`${
                currentPage === 'settings'
                  ? 'bg-blue-900 text-white'
                  : 'text-blue-200 hover:bg-blue-700 hover:text-white'
              } flex items-center w-full px-3 py-2 text-base font-medium`}
            >
              <Settings size={16} className="mr-2" />
              Settings
            </button>
            
            <button
              onClick={() => {
                onLogout();
                setMobileMenuOpen(false);
              }}
              className="text-blue-200 hover:bg-blue-700 hover:text-white flex items-center w-full px-3 py-2 text-base font-medium"
            >
              <LogOut size={16} className="mr-2" />
              Logout
            </button>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Navbar;