import React from 'react';
import { Shield, ExternalLink, Heart } from 'lucide-react';

const Footer = () => {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="bg-white border-t">
      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center mb-4 md:mb-0">
            <div className="h-8 w-8 rounded-full bg-blue-800 flex items-center justify-center mr-2">
              <Shield size={16} className="text-white" />
            </div>
            <span className="text-lg font-bold text-blue-800">WebVulnScanner</span>
          </div>
          
          <div className="flex space-x-8 mb-4 md:mb-0">
            <a href="#" className="text-gray-600 hover:text-blue-800 text-sm flex items-center transition-colors">
              About
              <ExternalLink size={12} className="ml-1" />
            </a>
            <a href="#" className="text-gray-600 hover:text-blue-800 text-sm flex items-center transition-colors">
              Privacy Policy
              <ExternalLink size={12} className="ml-1" />
            </a>
            <a href="#" className="text-gray-600 hover:text-blue-800 text-sm flex items-center transition-colors">
              Contact
              <ExternalLink size={12} className="ml-1" />
            </a>
          </div>
          
          <div className="text-sm text-gray-500 flex items-center">
            <span>© {currentYear} WebVulnScanner. All rights reserved.</span>
            <div className="ml-2 flex items-center text-red-500">
              <Heart size={14} className="fill-current" />
            </div>
          </div>
        </div>
        
        <div className="mt-6 pt-6 border-t border-gray-200">
          <div className="text-center text-xs text-gray-500">
            <p>WebVulnScanner is a tool designed to help identify and fix web vulnerabilities.</p>
            <p className="mt-1">Protect your applications from SQL Injection attacks, SSL vulnerabilities, and malicious content.</p>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;