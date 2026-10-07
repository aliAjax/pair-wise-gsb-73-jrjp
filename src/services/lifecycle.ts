import type {
  DataFlow,
  DataFlowStatus,
  DependencyStatus,
  ExternalDependency,
  ThreatModelState,
} from '@/models/domain'

export interface DependencyStatusChange {
  dependencyId: string
  targetStatus: DependencyStatus
  reason: string
  patch?: Partial<
    Pick<ExternalDependency, 'name' | 'vendor' | 'purpose' | 'dataClass' | 'owner'>
  >
}

export interface CascadeSummary {
  invalidatedFlows: string[]
  restoredFlows: string[]
  recalculatedThreats: string[]
  rescheduledTasks: string[]
  preservedDoneTasks: string[]
}

export interface DependencyStatusBatch {
  state: ThreatModelState
  auditIds: string[]
  summary: CascadeSummary
}

export const recomputeFlowStatus = (
  flow: Pick<DataFlow, 'externalDependencyIds'>,
  dependencies: ExternalDependency[],
): DataFlowStatus => {
  const hasRetiredDependency = flow.externalDependencyIds.some((id) =>
    dependencies.some((dependency) => dependency.id === id && dependency.status === 'retired'),
  )
  return hasRetiredDependency ? 'invalidated' : 'active'
}

export const dependencyTransitionLabel = (
  from: DependencyStatus,
  to: DependencyStatus,
): string => {
  if (to === 'retired') return '停服'
  if (to === 'active') return from === 'pending_verification' ? '确认在用' : '续期'
  if (to === 'review_due') return '确认待复核'
  return '待核'
}

/**
 * 构建“依赖状态变更”处置链批次：依赖状态 → 数据流失效重算 → 威胁结论重算 →
 * 缓解任务待重排（已完成任务保留原依据）。批次内审计事件使用确定性 ID，
 * 暂存后重放不会新增审计记录。
 */
export const buildDependencyStatusBatch = (
  state: ThreatModelState,
  change: DependencyStatusChange,
  batchId: string,
  now: string,
): DependencyStatusBatch | null => {
  const next = structuredClone(state)
  const dependency = next.dependencies.find((item) => item.id === change.dependencyId)
  if (!dependency) return null

  const previousStatus = dependency.status
  if (change.patch) Object.assign(dependency, change.patch)
  dependency.status = change.targetStatus
  dependency.revision += 1
  dependency.updatedAt = now

  const summary: CascadeSummary = {
    invalidatedFlows: [],
    restoredFlows: [],
    recalculatedThreats: [],
    rescheduledTasks: [],
    preservedDoneTasks: [],
  }

  // 1. 数据流立即失效重算：按当前全部依赖状态重新推导
  const changedFlowIds = new Set<string>()
  next.flows.forEach((flow) => {
    if (!flow.externalDependencyIds.includes(dependency.id)) return
    const recomputed = recomputeFlowStatus(flow, next.dependencies)
    if (recomputed === flow.status) return
    flow.status = recomputed
    changedFlowIds.add(flow.id)
    if (recomputed === 'invalidated') {
      summary.invalidatedFlows.push(flow.id)
    } else {
      summary.restoredFlows.push(flow.id)
    }
  })

  // 2. 威胁结论重算：直接关联该依赖，或关联到状态已变化的数据流
  const affectedThreatIds = new Set<string>()
  next.threats.forEach((threat) => {
    const linked =
      threat.externalDependencyIds.includes(dependency.id) ||
      threat.flowIds.some((flowId) => changedFlowIds.has(flowId))
    if (!linked) return
    threat.revision += 1
    if (threat.reviewStatus === 'approved') threat.reviewStatus = 'in_review'
    if (threat.status === 'mitigated' || threat.status === 'accepted') {
      threat.status = 'mitigating'
    }
    affectedThreatIds.add(threat.id)
    summary.recalculatedThreats.push(threat.id)
  })

  // 3. 缓解任务：未开始的回到待重排，已完成的保留原依据不动
  next.mitigations.forEach((task) => {
    if (!affectedThreatIds.has(task.threatId)) return
    if (task.status === 'todo') {
      task.status = 'reschedule'
      summary.rescheduledTasks.push(task.id)
    } else if (task.status === 'done') {
      summary.preservedDoneTasks.push(task.id)
    }
  })

  const actionLabel = dependencyTransitionLabel(previousStatus, change.targetStatus)
  const auditId = `aud-${batchId}`
  next.audit.unshift({
    id: auditId,
    entityType: 'dependency',
    entityId: dependency.id,
    action: actionLabel,
    actor: '当前用户',
    createdAt: now,
    detail: [
      `${dependency.name} ${actionLabel}。`,
      change.reason ? `原因：${change.reason}。` : '',
      `级联重算：${summary.invalidatedFlows.length} 条数据流失效、`,
      `${summary.restoredFlows.length} 条数据流恢复、`,
      `${summary.recalculatedThreats.length} 条威胁结论重算、`,
      `${summary.rescheduledTasks.length} 条未开始任务转为待重排、`,
      `${summary.preservedDoneTasks.length} 条已完成任务保留原依据。`,
    ].join(''),
  })

  return { state: next, auditIds: [auditId], summary }
}
