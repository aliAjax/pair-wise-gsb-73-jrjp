import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  DependencyStatus,
  DependencyTransitionConflict,
  DisposalBatch,
  ExternalDependency,
  MitigationTask,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  cloneState,
  createId,
  loadPendingBatch,
  loadState,
  readPersistedState,
  resetState,
  savePendingBatch,
  saveState,
  STORAGE_KEY,
} from '@/services/repository'
import {
  applyDisposalBatch,
  computeDependencyTransition,
  DEPENDENCY_STATUS_LABELS,
} from '@/services/disposalChain'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

export type TransitionOutcome =
  | { ok: true; batch: DisposalBatch }
  | { ok: false; reason: 'noop' }
  | { ok: false; reason: 'conflict'; conflict: DependencyTransitionConflict }
  | { ok: false; reason: 'write_failed'; batch: DisposalBatch }

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())
  const pendingBatch = ref<DisposalBatch | null>(loadPendingBatch())
  const dependencyConflicts = ref<DependencyTransitionConflict[]>([])

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  const persist = (): void => {
    data.value.stamp = createId('stamp')
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  // 其他窗口写入后同步本地状态；存在待恢复批次时不被覆盖
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
      if (event.key !== STORAGE_KEY || !event.newValue || pendingBatch.value) return
      const incoming = readPersistedState()
      if (incoming && incoming.stamp !== data.value.stamp) {
        data.value = incoming
        lastSavedAt.value = new Date().toISOString()
      }
    })
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  const saveEntity = <T extends IdentifiedEntity>(collection: CollectionKey, item: T): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  /**
   * 依赖停服/续期处置链入口。
   * 两个窗口同时提交时先到者生效：提交前比对持久化戳记，
   * 若另一窗口已变更同一依赖，则后到者保留草稿与冲突，不覆盖先到结果。
   */
  const applyDependencyTransition = (
    dependencyId: string,
    toStatus: DependencyStatus,
    baseStatus: DependencyStatus,
  ): TransitionOutcome => {
    const persisted = readPersistedState()
    if (persisted && persisted.stamp !== data.value.stamp) {
      const persistedDependency = persisted.dependencies.find((item) => item.id === dependencyId)
      if (persistedDependency && persistedDependency.status !== baseStatus) {
        data.value = persisted
        lastSavedAt.value = new Date().toISOString()
        const conflict: DependencyTransitionConflict = {
          id: createId('conflict'),
          dependencyId,
          dependencyName: persistedDependency.name,
          draftStatus: toStatus,
          currentStatus: persistedDependency.status,
          createdAt: new Date().toISOString(),
        }
        dependencyConflicts.value.unshift(conflict)
        return { ok: false, reason: 'conflict', conflict }
      }
      // 另一窗口的变更与本依赖无关：以其持久化状态为基线继续
      data.value = persisted
    }

    const batch = computeDependencyTransition(data.value, dependencyId, toStatus, {
      batchId: createId('batch'),
      actor: '当前用户',
      now: new Date().toISOString(),
    })
    if (!batch) return { ok: false, reason: 'noop' }

    const snapshot = cloneState(data.value)
    applyDisposalBatch(data.value, batch)
    try {
      persist()
    } catch {
      // 写入失败：回滚到批次前状态，完整批次保留待重放
      data.value = snapshot
      pendingBatch.value = batch
      savePendingBatch(batch)
      return { ok: false, reason: 'write_failed', batch }
    }
    return { ok: true, batch }
  }

  /** 重放写入失败的完整批次；审计按批次内固定 ID 去重，重放不新增审计。 */
  const replayPendingBatch = (): boolean => {
    const batch = pendingBatch.value
    if (!batch) return false
    const snapshot = cloneState(data.value)
    applyDisposalBatch(data.value, batch)
    try {
      persist()
    } catch {
      data.value = snapshot
      return false
    }
    pendingBatch.value = null
    savePendingBatch(null)
    return true
  }

  const discardPendingBatch = (): void => {
    pendingBatch.value = null
    savePendingBatch(null)
  }

  const dismissDependencyConflict = (conflictId: string): void => {
    dependencyConflicts.value = dependencyConflicts.value.filter(
      (item) => item.id !== conflictId,
    )
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    persist()
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): { ok: boolean; error?: string } => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return { ok: false, error: '威胁不存在' }
    if (decision === 'approved') {
      const pendingVendors = threat.externalDependencyIds
        .map((id) => data.value.dependencies.find((item) => item.id === id))
        .filter(
          (item): item is ExternalDependency => item?.vendorStatus === 'pending',
        )
      if (pendingVendors.length > 0) {
        return {
          ok: false,
          error: `关联依赖 ${pendingVendors.map((item) => item.name).join('、')} 的供应商状态仍待核，补齐前不能批准会签`,
        }
      }
    }
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
    const requiredRoles: ActorRole[] = ['development', 'security', 'business']
    const allSubmitted = requiredRoles.every((requiredRole) =>
      currentDecisions.some((item) => item.role === requiredRole),
    )
    if (currentDecisions.some((item) => item.decision === 'rejected')) {
      threat.reviewStatus = 'rejected'
    } else if (
      allSubmitted &&
      currentDecisions.every((item) => item.decision === 'approved')
    ) {
      threat.reviewStatus = 'approved'
    } else {
      threat.reviewStatus = 'in_review'
    }

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    persist()
    return { ok: true }
  }

  const buildCompletionBasis = (task: MitigationTask): string => {
    const threat = data.value.threats.find((item) => item.id === task.threatId)
    const dependencies = (threat?.externalDependencyIds ?? [])
      .map((id) => data.value.dependencies.find((item) => item.id === id))
      .filter((item): item is ExternalDependency => Boolean(item))
    const dependencyPart =
      dependencies.length > 0
        ? dependencies
            .map((item) => `${item.name}=${DEPENDENCY_STATUS_LABELS[item.status]}`)
            .join('，')
        : '无关联外部依赖'
    return `完成于威胁 v1.${threat?.revision ?? data.value.currentRevision}；${dependencyPart}`
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    if (status === 'done' && !task.completedAt) {
      // 已完成结果保留原依据：记录完成时刻的威胁版本与依赖状态
      task.completedAt = new Date().toISOString()
      task.completedBasis = buildCompletionBasis(task)
    }
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  const resetDemo = (): void => {
    pendingBatch.value = null
    savePendingBatch(null)
    dependencyConflicts.value = []
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
  }

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 外部依赖处置',
      ...data.value.dependencies.map(
        (dependency) =>
          `- ${dependency.name}（${dependency.vendor}）：${DEPENDENCY_STATUS_LABELS[dependency.status]}，供应商${dependency.vendorStatus === 'confirmed' ? '已确认' : '待核'}`,
      ),
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    metrics,
    issues,
    pendingReviews,
    pendingBatch,
    dependencyConflicts,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    applyDependencyTransition,
    replayPendingBatch,
    discardPendingBatch,
    dismissDependencyConflict,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
