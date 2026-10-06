import { useLayoutEffect, useRef, useState, useSyncExternalStore } from 'react';
import { MOBILE_QUERY } from './responsive';

function subscribe(listener: () => void) {
  const media = window.matchMedia(MOBILE_QUERY);
  media.addEventListener('change', listener);
  return () => media.removeEventListener('change', listener);
}
export function useIsMobile() {
  return useSyncExternalStore(subscribe, () => window.matchMedia(MOBILE_QUERY).matches, () => false);
}

// Ant's virtual table needs a numeric width. Measure its container, not the
// screen: cards, safe areas and the navigation all change the usable space.
export function useContentWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(1);
  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => setWidth(Math.max(1, Math.floor(node.clientWidth)));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  return { ref, width };
}
