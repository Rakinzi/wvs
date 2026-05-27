import { useCallback, useEffect, useState } from 'react';
import { apiJson, ApiError } from '../lib/api';

export const useUptimeMonitorsData = () => {
  const [monitors, setMonitors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchMonitors = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiJson('/uptime-monitors', { auth: true });
      if (data.status === 'success') {
        setMonitors(data.monitors || []);
      } else {
        throw new Error(data.message || 'Failed to load uptime monitors');
      }
    } catch (nextError) {
      setError(nextError.message || 'Failed to load uptime monitors');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMonitors();
    const intervalId = setInterval(fetchMonitors, 60000);
    return () => clearInterval(intervalId);
  }, [fetchMonitors]);

  const createMonitor = useCallback(async (payload) => {
    const { data } = await apiJson('/uptime-monitors', {
      method: 'POST',
      auth: true,
      json: true,
      body: payload,
    });
    if (data.status !== 'success') {
      throw new Error(data.message || 'Failed to create monitor');
    }
    await fetchMonitors();
    return data.monitor;
  }, [fetchMonitors]);

  const updateMonitor = useCallback(async (monitorId, payload) => {
    const { data } = await apiJson(`/uptime-monitors/${monitorId}`, {
      method: 'PATCH',
      auth: true,
      json: true,
      body: payload,
    });
    if (data.status !== 'success') {
      throw new Error(data.message || 'Failed to update monitor');
    }
    setMonitors((prev) => prev.map((monitor) => monitor.id === monitorId ? data.monitor : monitor));
    return data.monitor;
  }, []);

  const runCheck = useCallback(async (monitorId) => {
    const { data } = await apiJson(`/uptime-monitors/${monitorId}/check`, {
      method: 'POST',
      auth: true,
      json: true,
      body: {},
    });
    if (data.status !== 'success') {
      throw new Error(data.message || 'Failed to run uptime check');
    }
    setMonitors((prev) => prev.map((monitor) => monitor.id === monitorId ? data.monitor : monitor));
    return data.monitor;
  }, []);

  const deleteMonitor = useCallback(async (monitorId) => {
    try {
      const { data } = await apiJson(`/uptime-monitors/${monitorId}`, {
        method: 'DELETE',
        auth: true,
        json: true,
        body: {},
      });
      if (data.status !== 'success') {
        throw new Error(data.message || 'Failed to delete monitor');
      }
      setMonitors((prev) => prev.filter((monitor) => monitor.id !== monitorId));
    } catch (nextError) {
      if (nextError instanceof ApiError) {
        throw nextError;
      }
      throw new Error('Failed to delete monitor');
    }
  }, []);

  return {
    monitors,
    loading,
    error,
    fetchMonitors,
    createMonitor,
    updateMonitor,
    runCheck,
    deleteMonitor,
  };
};

