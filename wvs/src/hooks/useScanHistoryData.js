import { useState, useEffect, useCallback } from 'react';
import { apiJson, ApiError } from '../lib/api';

export const useScanHistoryData = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const { data } = await apiJson('/scans/history?limit=100', { auth: true });
      if (data.status === 'success' && data.scans) {
        setScans(data.scans);
      } else {
        setScans([]);
      }
    } catch (error) {
      setError(error instanceof ApiError ? error.message : 'Failed to connect to server');
    } finally {
      setLoading(false);
    }
  }, []);

  const deleteScan = useCallback(async (scanId) => {
    await apiJson(`/scans/${scanId}`, { method: 'DELETE', auth: true });
    setScans(prev => prev.filter(s => s.id !== scanId));
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  return {
    error,
    fetchScans,
    deleteScan,
    loading,
    scans
  };
};
