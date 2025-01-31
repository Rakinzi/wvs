import React from 'react';
import Sidebar from '../../components/dashboard/sidebar';
import Header from '../../components/dashboard/header';

const DashboardLayout = ({ children }) => {
  return (
    <div className="min-h-screen relative">
      <Sidebar />
      <main className="md:pl-72">
        <Header />
        <div className="p-4 pt-4 bg-gray-100">
          {children}
        </div>
      </main>
    </div>
  );
};

export default DashboardLayout;