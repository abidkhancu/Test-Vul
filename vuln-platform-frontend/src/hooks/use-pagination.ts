"use client";

import { useEffect, useRef, useState } from "react";

// Shared page/pageSize state for the four backend-paginated tables
// (findings, hosts, remediation, audit). `resetKey` should be
// whatever the caller's filter state serializes to (e.g.
// `${search}|${severity}|${status}`) — changing filters and staying
// on page 4 of the old result set is a common source of "empty page"
// confusion, so this resets to page 1 whenever the filters change,
// but not when only the page itself changes.
export function usePagination(resetKey: string, initialPageSize = 50) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const previousResetKey = useRef(resetKey);

  useEffect(() => {
    if (previousResetKey.current !== resetKey) {
      previousResetKey.current = resetKey;
      setPage(1);
    }
  }, [resetKey]);

  function changePageSize(size: number) {
    setPageSize(size);
    setPage(1);
  }

  return { page, pageSize, setPage, setPageSize: changePageSize };
}
