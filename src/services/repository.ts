import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const PENDING_BATCH_KEY = 'scapex-threat-model-pending-batch'

interface StagedBatch {
  batchId: string
  auditIds: string[]
  state: ThreatModelState
}

/**
 * 旧数据迁移：缺少供应商或状态的依赖先置为“待核”，
 * 并补齐后续版本引入的数据流状态、依赖修订号等字段。
 */
export const migrateState = (state: ThreatModelState): ThreatModelState => {
  state.dependencies = (state.dependencies ?? []).map((dependency) => ({
    ...dependency,
    vendor: dependency.vendor ?? '',
    revision: dependency.revision ?? 1,
    updatedAt: dependency.updatedAt ?? '2026-09-01T00:00:00+08:00',
    status:
      !dependency.status || !(dependency.vendor ?? '').trim()
        ? 'pending_verification'
        : dependency.status,
  }))
  state.flows = (state.flows ?? []).map((flow) => ({
    ...flow,
    externalDependencyIds: flow.externalDependencyIds ?? [],
    status: flow.status ?? 'active',
  }))
  state.mitigations = (state.mitigations ?? []).map((task) => ({
    ...task,
    status: task.status ?? 'todo',
  }))
  state.dependencyConflicts = state.dependencyConflicts ?? []
  return state
}

/**
 * 写入失败后从完整批次恢复：暂存区中的批次带有确定性审计 ID，
 * 若主状态已包含这些审计记录则视为已应用，直接丢弃暂存；
 * 否则整体重放暂存状态，重放不会新增审计。
 */
const recoverPendingBatch = (state: ThreatModelState): ThreatModelState => {
  const raw = localStorage.getItem(PENDING_BATCH_KEY)
  if (!raw) return state
  localStorage.removeItem(PENDING_BATCH_KEY)
  try {
    const staged = JSON.parse(raw) as StagedBatch
    const alreadyApplied = staged.auditIds.every((id) =>
      state.audit.some((event) => event.id === id),
    )
    return alreadyApplied ? state : migrateState(staged.state)
  } catch {
    return state
  }
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }
  let state: ThreatModelState
  try {
    state = migrateState(JSON.parse(raw) as ThreatModelState)
  } catch {
    state = createSeedState()
  }
  state = recoverPendingBatch(state)
  // 仅在迁移或批次恢复真正改变了内容时才回写，避免只读路径产生多余写入
  const serialized = JSON.stringify(state)
  if (serialized !== raw) {
    localStorage.setItem(STORAGE_KEY, serialized)
  }
  return state
}

export const saveState = (state: ThreatModelState): void => {
  // 状态可能是 Vue 响应式代理，不能直接 structuredClone；JSON 序列化即完成脱离
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

/**
 * 以“完整批次”方式提交：先暂存整批状态，再写入主存储，最后清理暂存。
 * 任一步失败时暂存批次保留，下一次 loadState 或显式恢复可整体重放。
 */
export const commitBatch = (
  batchId: string,
  auditIds: string[],
  state: ThreatModelState,
): void => {
  const staged: StagedBatch = { batchId, auditIds, state }
  localStorage.setItem(PENDING_BATCH_KEY, JSON.stringify(staged))
  saveState(state)
  localStorage.removeItem(PENDING_BATCH_KEY)
}

export const hasPendingBatch = (): boolean =>
  Boolean(localStorage.getItem(PENDING_BATCH_KEY))

export const resetState = (): ThreatModelState => {
  localStorage.removeItem(PENDING_BATCH_KEY)
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
