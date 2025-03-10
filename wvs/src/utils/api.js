import { cookies } from 'next/headers';

const API_URL = 'http://localhost:5000';

export async function fetchWithAuth(endpoint, options = {}) {
  const cookieStore = cookies();
  const token = cookieStore.get('token')?.value;
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'API request failed');
  }

  return data;
}