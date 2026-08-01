/**
 * 页面局部异步状态的小工具（不进 bns_model 的 store 体系）。
 */

import { useCallback, useEffect, useRef, useState } from 'react'

export interface LocalAsync<T> {
  status: 'idle' | 'loading' | 'ready' | 'error'
  data: T | null
  error: unknown
}

export function useAsync<T>(
  factory: (() => Promise<T>) | null,
  deps: unknown[],
): LocalAsync<T> & { reload: () => void } {
  const [state, setState] = useState<LocalAsync<T>>({ status: 'idle', data: null, error: null })
  const generation = useRef(0)

  const run = useCallback(() => {
    if (!factory) {
      setState({ status: 'idle', data: null, error: null })
      return
    }
    const current = (generation.current += 1)
    setState((previous) => ({ ...previous, status: 'loading', error: null }))
    factory().then(
      (data) => {
        if (generation.current === current) setState({ status: 'ready', data, error: null })
      },
      (error: unknown) => {
        if (generation.current === current) setState({ status: 'error', data: null, error })
      },
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    run()
  }, [run])

  return { ...state, reload: run }
}
