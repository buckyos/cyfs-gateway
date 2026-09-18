/**
 * MVC 中 Model 的通知机制：极小的可观察容器 + 异步数据状态。
 *
 * 只依赖引用相等触发通知，配合 React 的 `useSyncExternalStore` 使用，
 * 不引入任何第三方状态库。
 */

import type { BnsError } from '../types/errors'

export type Unsubscribe = () => void

export class Store<T> {
  private value: T
  private readonly listeners = new Set<(value: T) => void>()

  constructor(initial: T) {
    this.value = initial
  }

  get(): T {
    return this.value
  }

  set(next: T): void {
    if (Object.is(next, this.value)) return
    this.value = next
    for (const listener of this.listeners) listener(next)
  }

  update(updater: (prev: T) => T): void {
    this.set(updater(this.value))
  }

  subscribe(listener: (value: T) => void): Unsubscribe {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }
}

/** 只读视图，交给 View 层，避免视图直接写 Model。 */
export interface ReadonlyStore<T> {
  get(): T
  subscribe(listener: (value: T) => void): Unsubscribe
}

export type AsyncStatus = 'idle' | 'loading' | 'ready' | 'error'

/**
 * 统一的异步读状态。
 *
 * `data` 在 loading / error 时保留上一次的值，视图可以在刷新时继续显示旧数据
 * 并用 `loadedAt` 提示新鲜度 —— 这是 PRD 要求的“投影延迟可见”而不是白屏。
 */
export interface AsyncState<T> {
  status: AsyncStatus
  data: T | null
  error: BnsError | null
  /** 最近一次成功加载的时间戳（ms）。 */
  loadedAt: number | null
}

export function idleState<T>(): AsyncState<T> {
  return { status: 'idle', data: null, error: null, loadedAt: null }
}

export function loadingState<T>(prev?: AsyncState<T>): AsyncState<T> {
  return {
    status: 'loading',
    data: prev?.data ?? null,
    error: null,
    loadedAt: prev?.loadedAt ?? null,
  }
}

export function readyState<T>(data: T, now: number): AsyncState<T> {
  return { status: 'ready', data, error: null, loadedAt: now }
}

export function errorState<T>(error: BnsError, now: number, prev?: AsyncState<T>): AsyncState<T> {
  return {
    status: 'error',
    data: prev?.data ?? null,
    error,
    loadedAt: prev?.loadedAt ?? now,
  }
}

export function isStale(state: AsyncState<unknown>, ttlMs: number, now: number): boolean {
  if (state.loadedAt === null) return true
  return now - state.loadedAt > ttlMs
}

/**
 * 同 key 的并发请求合并成一次（single-flight）。
 * 名称详情页 8 个 tab 会重复请求同一个 `name.query_state`，没有它就是 N 倍放大。
 */
export class RequestDeduper {
  private readonly inflight = new Map<string, Promise<unknown>>()

  run<T>(key: string, factory: () => Promise<T>): Promise<T> {
    const existing = this.inflight.get(key)
    if (existing) return existing as Promise<T>
    const promise = factory().finally(() => {
      this.inflight.delete(key)
    })
    this.inflight.set(key, promise)
    return promise
  }
}
