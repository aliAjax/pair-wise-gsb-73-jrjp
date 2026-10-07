import type { DisposalBatch, ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

export const STORAGE_KEY = 'scapex-threat-model-v1'
const PENDING_BATCH_KEY = 'scapex-threat-model-pending-batch-v1'

// 状态为纯 JSON 数据；响应式代理无法走 structuredClone，统一用 JSON 深拷贝
export const cloneState = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

/**
 * 旧版本数据迁移：
 * - 缺少供应商状态的依赖先标记为「待核」，补齐前关联威胁不能批准会签；
 * - 缺少状态的数据流视为有效；
 * - 缺少并发戳记的状态补发新戳记。
 */
export const migrateState = (state: ThreatModelState): ThreatModelState => {
  state.dependencies.forEach((dependency) => {
    if (!dependency.vendorStatus) dependency.vendorStatus = 'pending'
  })
  state.flows.forEach((flow) => {
    if (!flow.status) flow.status = 'active'
  })
  if (!state.stamp) state.stamp = createId('stamp')
  return state
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  try {
    const migrated = migrateState(JSON.parse(raw) as ThreatModelState)
    // 迁移结果写回，旧数据的待核标记与并发戳记随之固化
    localStorage.setItem(STORAGE_KEY, JSON.stringify(migrated))
    return migrated
  } catch {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }
}

export const readPersistedState = (): ThreatModelState | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    return migrateState(JSON.parse(raw) as ThreatModelState)
  } catch {
    return null
  }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cloneState(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const loadPendingBatch = (): DisposalBatch | null => {
  try {
    const raw = localStorage.getItem(PENDING_BATCH_KEY)
    return raw ? (JSON.parse(raw) as DisposalBatch) : null
  } catch {
    return null
  }
}

export const savePendingBatch = (batch: DisposalBatch | null): void => {
  try {
    if (batch) {
      localStorage.setItem(PENDING_BATCH_KEY, JSON.stringify(batch))
    } else {
      localStorage.removeItem(PENDING_BATCH_KEY)
    }
  } catch {
    // 兜底写入失败时批次仍保留在内存中，等待下次重放
  }
}
