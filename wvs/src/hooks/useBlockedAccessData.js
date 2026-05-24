import { useState, useEffect, useCallback } from 'react';
import { clearSession } from '../lib/auth';
import { apiJson, ApiError } from '../lib/api';

const REQUESTS_PER_PAGE = 10;

export const useBlockedAccessData = (currentPage) => {
  const [blockedRequests, setBlockedRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);

  const fetchBlockedRequests = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const offset = (currentPage - 1) * REQUESTS_PER_PAGE;
      const { data } = await apiJson(
        `/blocked-access/list?limit=${REQUESTS_PER_PAGE}&offset=${offset}`,
        { auth: true }
      );

      if (data.status === 'success') {
        setBlockedRequests(data.blocked_requests || []);
        setTotalCount(data.total || 0);
      } else {
        setError(data.message || 'Failed to fetch blocked access attempts');
        setBlockedRequests([]);
        setTotalCount(0);
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setError('Your session has expired. Please login again.');
        clearSession();
      } else if (error instanceof ApiError && error.status === 403) {
        setError('You do not have permission to view this data.');
      } else {
        setError('Failed to connect to server. Please check your connection and try again.');
      }
      setBlockedRequests([]);
      setTotalCount(0);
    } finally {
      setLoading(false);
    }
  }, [currentPage]);

  useEffect(() => {
    fetchBlockedRequests();
  }, [fetchBlockedRequests]);

  return {
    blockedRequests,
    error,
    fetchBlockedRequests,
    loading,
    requestsPerPage: REQUESTS_PER_PAGE,
    totalCount
  };
};
