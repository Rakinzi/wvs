import { useState, useEffect, useCallback } from 'react';
import { apiJson, ApiError } from '../lib/api';

export const useBlockedSitesData = () => {
  const [blockedSites, setBlockedSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [addingUrl, setAddingUrl] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  const fetchBlockedSites = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiJson('/api/malicious/list?limit=1000', { auth: true });

      const sites = data.sites || data.domains.map((domain, index) => ({
        id: index + 1,
        domain,
        url: `http://${domain}`,
        reason: 'Blocked domain',
        source: 'unknown',
        date_added: new Date().toISOString()
      }));

      setBlockedSites(sites);
    } catch (error) {
      setError(error instanceof ApiError ? error.message : 'Failed to connect to server');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlockedSites();
  }, [fetchBlockedSites]);

  const addBlockedSite = useCallback(async ({ url, reason }) => {
    setAddingUrl(true);
    setError(null);

    try {
      const { data } = await apiJson('/api/malicious/add', {
        method: 'POST',
        auth: true,
        json: true,
        body: {
          url,
          reason: reason || 'Manually blocked'
        }
      });

      setSuccessMessage(data.message || 'Site added successfully');
      await fetchBlockedSites();
      setTimeout(() => {
        setSuccessMessage('');
      }, 3000);
      return true;
    } catch (error) {
      setError(error instanceof ApiError ? error.message : 'Failed to connect to server');
      return false;
    } finally {
      setAddingUrl(false);
    }
  }, [fetchBlockedSites]);

  const removeBlockedSite = useCallback((siteId) => {
    setBlockedSites(prev => prev.filter(site => site.id !== siteId));
    setSuccessMessage('Site removed successfully');
    setTimeout(() => {
      setSuccessMessage('');
    }, 3000);
  }, []);

  return {
    addBlockedSite,
    addingUrl,
    blockedSites,
    error,
    fetchBlockedSites,
    loading,
    removeBlockedSite,
    successMessage
  };
};
