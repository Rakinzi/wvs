import { useState, useEffect, useCallback } from 'react';
import { apiJson, ApiError } from '../lib/api';

export const useScanReportData = (scanId) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchReport = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const { data } = await apiJson(`/report/${scanId}?format=json`, { auth: true });
      setReport(data);
    } catch (error) {
      setError(error instanceof ApiError ? error.message : 'Failed to connect to server');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  return {
    error,
    fetchReport,
    loading,
    report
  };
};
