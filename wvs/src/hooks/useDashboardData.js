import { useState, useEffect, useCallback } from 'react';
import { apiJson } from '../lib/api';

export const useDashboardData = () => {
  const [dashboardStats, setDashboardStats] = useState(null);
  const [recentScanJobs, setRecentScanJobs] = useState([]);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);

  const fetchDashboardStats = useCallback(async () => {
    setIsLoadingStats(true);
    setStatsError(null);
    try {
      const { data } = await apiJson('/api/dashboard/stats', { auth: true });
      if (data.status === 'success') {
        setDashboardStats(data.stats);
      } else {
        throw new Error(data.message || 'Failed to load dashboard statistics');
      }
    } catch (error) {
      setStatsError(error.message || 'Failed to load dashboard statistics');
      console.error(error);
    } finally {
      setIsLoadingStats(false);
    }
  }, []);

  const fetchRecentScanJobs = useCallback(async () => {
    try {
      const { data } = await apiJson('/scan/jobs?limit=5', { auth: true });
      if (data.status === 'success') {
        setRecentScanJobs(data.jobs || []);
      }
    } catch (error) {
      console.error('Error fetching recent scan jobs:', error);
    }
  }, []);

  const refreshDashboard = useCallback(async () => {
    await Promise.all([fetchDashboardStats(), fetchRecentScanJobs()]);
  }, [fetchDashboardStats, fetchRecentScanJobs]);

  useEffect(() => {
    refreshDashboard();
    const refreshInterval = setInterval(refreshDashboard, 60000);
    return () => clearInterval(refreshInterval);
  }, [refreshDashboard]);

  return {
    dashboardStats,
    fetchDashboardStats: refreshDashboard,
    isLoadingStats,
    statsError,
    recentScanJobs,
  };
};
