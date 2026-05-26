import { useCallback, useEffect, useState } from 'react';
import { apiJson, ApiError } from '../lib/api';

export const useVerifiedTargetsData = () => {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchTargets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiJson('/targets', { auth: true });
      setTargets(data.targets || []);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load verified targets');
      setTargets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  const createTarget = useCallback(async (payload) => {
    const { data } = await apiJson('/targets', {
      method: 'POST',
      auth: true,
      json: true,
      body: payload,
    });
    await fetchTargets();
    return data;
  }, [fetchTargets]);

  const verifyTarget = useCallback(async (targetId, token) => {
    const { data } = await apiJson(`/targets/${targetId}/verify`, {
      method: 'POST',
      auth: true,
      json: true,
      body: { token },
    });
    await fetchTargets();
    return data;
  }, [fetchTargets]);

  const regenerateToken = useCallback(async (targetId) => {
    const { data } = await apiJson(`/targets/${targetId}/verification-token`, {
      method: 'POST',
      auth: true,
      json: true,
      body: {},
    });
    await fetchTargets();
    return data;
  }, [fetchTargets]);

  const deleteTarget = useCallback(async (targetId) => {
    await apiJson(`/targets/${targetId}`, {
      method: 'DELETE',
      auth: true,
    });
    await fetchTargets();
  }, [fetchTargets]);

  return {
    targets,
    loading,
    error,
    fetchTargets,
    createTarget,
    verifyTarget,
    regenerateToken,
    deleteTarget,
  };
};
