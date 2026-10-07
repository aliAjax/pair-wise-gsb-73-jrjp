import type {
  AuditEvent,
  DataFlow,
  DependencyStatus,
  DisposalBatch,
  ExternalDependency,
  MitigationTask,
  Threat,
  ThreatModelState,
} from '@/models/domain'

export const DEPENDENCY_STATUS_LABELS: Record<DependencyStatus, string> = {
  active: '有效',
  review_due: '待续期评估',
  retired: '已停服',
}

export interface TransitionContext {
  batchId: string
  actor: string
  now: string
}

const recalculateThreat = (threat: Threat, currentRevision: number): Threat => {
  let next = threat
  if (next.reviewStatus === 'approved') {
    next = { ...next, reviewStatus: 'in_review', revision: currentRevision + 1 }
  }
  if (next.status === 'mitigated') {
    next = { ...next, status: 'mitigating' }
  } else if (next.status === 'accepted') {
    next = { ...next, status: 'open' }
  }
  return next
}

/**
 * 计算依赖状态变更的完整处置批次：
 * 依赖状态 → 关联数据流失效/重算 → 威胁结论重回会签 → 未开始任务待重排。
 * 已完成任务不在批次内，保留原完成依据。
 */
export const computeDependencyTransition = (
  state: ThreatModelState,
  dependencyId: string,
  toStatus: DependencyStatus,
  context: TransitionContext,
): DisposalBatch | null => {
  const dependency = state.dependencies.find((item) => item.id === dependencyId)
  if (!dependency || dependency.status === toStatus) return null

  const fromStatus = dependency.status
  const audit: AuditEvent[] = []
  const pushAudit = (
    suffix: string,
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    audit.push({
      id: `aud-${context.batchId}-${suffix}`,
      entityType,
      entityId,
      action,
      actor: context.actor,
      createdAt: context.now,
      detail,
    })
  }

  const nextDependency: ExternalDependency = {
    ...dependency,
    status: toStatus,
    statusChangedAt: context.now,
  }
  pushAudit(
    'dep',
    'dependencies',
    dependency.id,
    '依赖状态变更',
    `${dependency.name}（${dependency.vendor}）由「${DEPENDENCY_STATUS_LABELS[fromStatus]}」调整为「${DEPENDENCY_STATUS_LABELS[toStatus]}」，处置链已联动重算。`,
  )

  const linkedFlows = state.flows.filter((flow) => flow.externalDependencyId === dependencyId)
  const flows: DataFlow[] = []
  linkedFlows.forEach((flow) => {
    if (toStatus === 'retired' && flow.status !== 'invalid') {
      flows.push({
        ...flow,
        status: 'invalid',
        invalidatedByDependencyId: dependencyId,
        statusNote: `依赖「${dependency.name}」已停服，数据流立即失效，等待重算。`,
      })
      pushAudit(
        `flow-${flow.id}`,
        'flows',
        flow.id,
        '数据流失效',
        `${flow.name} 因依赖「${dependency.name}」停服而失效，已进入重算。`,
      )
    } else if (
      toStatus === 'active' &&
      flow.status === 'invalid' &&
      flow.invalidatedByDependencyId === dependencyId
    ) {
      flows.push({
        ...flow,
        status: 'active',
        invalidatedByDependencyId: undefined,
        statusNote: `依赖「${dependency.name}」已续期，数据流重算后恢复有效。`,
      })
      pushAudit(
        `flow-${flow.id}`,
        'flows',
        flow.id,
        '数据流重算恢复',
        `${flow.name} 随依赖「${dependency.name}」续期完成重算，恢复有效。`,
      )
    }
  })

  const linkedFlowIds = new Set(linkedFlows.map((flow) => flow.id))
  const linkedThreatIds = new Set(
    state.threats
      .filter(
        (threat) =>
          threat.externalDependencyIds.includes(dependencyId) ||
          threat.flowIds.some((flowId) => linkedFlowIds.has(flowId)),
      )
      .map((threat) => threat.id),
  )

  const threats: Threat[] = []
  state.threats.forEach((threat) => {
    if (!linkedThreatIds.has(threat.id)) return
    const next = recalculateThreat(threat, state.currentRevision)
    if (next !== threat) {
      threats.push(next)
      pushAudit(
        `thr-${threat.id}`,
        'threats',
        threat.id,
        '威胁结论重算',
        `${threat.code} 的结论依据随依赖「${dependency.name}」状态变更失效，回到会签流程重新确认。`,
      )
    }
  })

  const mitigations: MitigationTask[] = []
  state.mitigations.forEach((task) => {
    if (!linkedThreatIds.has(task.threatId)) return
    if (task.status === 'todo') {
      mitigations.push({ ...task, status: 'reschedule' })
      pushAudit(
        `mit-${task.id}`,
        'mitigations',
        task.id,
        '任务待重排',
        `${task.title} 尚未开始，依赖状态变更后回到待重排；已完成任务保留原完成依据。`,
      )
    }
  })

  return {
    id: context.batchId,
    dependencyId,
    fromStatus,
    toStatus,
    createdAt: context.now,
    actor: context.actor,
    dependency: nextDependency,
    flows,
    threats,
    mitigations,
    audit,
  }
}

const replaceById = <T extends { id: string }>(collection: T[], item: T): void => {
  const index = collection.findIndex((entry) => entry.id === item.id)
  if (index >= 0) collection[index] = item
}

/**
 * 把完整批次应用到状态上。审计事件使用批次内固定 ID 并去重，
 * 因此同一批次重放不会产生新的审计记录。
 */
export const applyDisposalBatch = (state: ThreatModelState, batch: DisposalBatch): void => {
  replaceById(state.dependencies, batch.dependency)
  batch.flows.forEach((flow) => replaceById(state.flows, flow))
  batch.threats.forEach((threat) => replaceById(state.threats, threat))
  batch.mitigations.forEach((task) => replaceById(state.mitigations, task))

  const known = new Set(state.audit.map((event) => event.id))
  ;[...batch.audit].reverse().forEach((event) => {
    if (!known.has(event.id)) {
      state.audit.unshift(event)
      known.add(event.id)
    }
  })
}
