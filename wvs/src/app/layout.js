import './globals.css';

export const metadata = {
  title: 'Admin Dashboard',
  description: 'Admin Dashboard for E-commerce',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {children}
      </body>
    </html>
  );
}