import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  DependencyConflict,
  DependencyStatus,
  ExternalDependency,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  commitBatch,
  createId,
  hasPendingBatch,
  loadState,
  resetState,
  saveState,
} from '@/services/repository'
import {
  buildDependencyStatusBatch,
  dependencyTransitionLabel,
  type DependencyStatusChange,
} from '@/services/lifecycle'
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

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())
  const pendingRecovery = ref(false)

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )
  const dependencyConflicts = computed(() => data.value.dependencyConflicts)

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
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

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (collection === 'dependencies') {
      // 依赖的任何字段变更都推进修订号，使其他窗口的停服/续期草稿能检测到冲突
      const dependency = item as ExternalDependency
      const previous =
        index >= 0 ? (target[index] as unknown as ExternalDependency) : undefined
      dependency.revision = (previous?.revision ?? 0) + 1
      dependency.updatedAt = new Date().toISOString()
    }
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
  ): { blockedBy: string[] } => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return { blockedBy: [] }
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
    // 待核依赖未补齐前，即使三方全部通过也不能批准会签
    const unverifiedDependencies = data.value.dependencies.filter(
      (dependency) =>
        threat.externalDependencyIds.includes(dependency.id) &&
        dependency.status === 'pending_verification',
    )
    let blockedBy: string[] = []
    if (currentDecisions.some((item) => item.decision === 'rejected')) {
      threat.reviewStatus = 'rejected'
    } else if (
      allSubmitted &&
      currentDecisions.every((item) => item.decision === 'approved')
    ) {
      if (unverifiedDependencies.length > 0) {
        threat.reviewStatus = 'in_review'
        blockedBy = unverifiedDependencies.map((dependency) => dependency.name)
      } else {
        threat.reviewStatus = 'approved'
      }
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
      blockedBy.length > 0
        ? `${actor}（${role}）提交会签意见；外部依赖待核（${blockedBy.join('、')}），补齐前不能批准会签`
        : `${actor}（${role}）提交会签意见`,
    )
    persist()
    return { blockedBy }
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    if (status === 'done' && task.status !== 'done') {
      // 完成时固化依据：后续依赖停服级联不会改动已完成任务，原依据保留
      task.completedAt = new Date().toISOString()
      task.basisRevision = data.value.currentRevision
    }
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  /**
   * 依赖状态变更（停服/续期/补齐确认）的统一入口。
   * 基于 localStorage 中的最新状态做修订号校验：先到者生效并级联重算，
   * 后到者保留草稿与冲突记录。批次写入失败时完整批次进入暂存区待恢复。
   */
  const changeDependencyStatus = (input: {
    dependencyId: string
    targetStatus: DependencyStatus
    reason: string
    baseRevision: number
    patch?: DependencyStatusChange['patch']
  }): { ok: boolean; conflict?: DependencyConflict; error?: string } => {
    let persisted: ThreatModelState
    try {
      persisted = loadState()
    } catch {
      return { ok: false, error: '读取最新状态失败，请检查浏览器存储空间' }
    }
    const dependency = persisted.dependencies.find((item) => item.id === input.dependencyId)
    if (!dependency) {
      return { ok: false, error: '依赖不存在或已被删除' }
    }

    if (dependency.revision !== input.baseRevision) {
      const conflict: DependencyConflict = {
        id: createId('conf'),
        dependencyId: dependency.id,
        dependencyName: dependency.name,
        targetStatus: input.targetStatus,
        reason: input.reason,
        baseRevision: input.baseRevision,
        currentRevision: dependency.revision,
        actor: '当前用户',
        createdAt: new Date().toISOString(),
      }
      persisted.dependencyConflicts.unshift(conflict)
      persisted.audit.unshift({
        id: createId('aud'),
        entityType: 'dependency',
        entityId: dependency.id,
        action: '提交冲突',
        actor: '当前用户',
        createdAt: new Date().toISOString(),
        detail: `基于修订 v${input.baseRevision} 的${dependencyTransitionLabel(dependency.status, input.targetStatus)}提交与最新修订 v${dependency.revision} 冲突，先到者已生效，草稿与冲突已保留。`,
      })
      try {
        saveState(persisted)
      } catch {
        return { ok: false, error: '冲突记录写入失败，请检查浏览器存储空间', conflict }
      }
      data.value = persisted
      lastSavedAt.value = new Date().toISOString()
      return { ok: false, conflict }
    }

    const batchId = createId('batch')
    const batch = buildDependencyStatusBatch(
      persisted,
      {
        dependencyId: input.dependencyId,
        targetStatus: input.targetStatus,
        reason: input.reason,
        patch: input.patch,
      },
      batchId,
      new Date().toISOString(),
    )
    if (!batch) {
      return { ok: false, error: '依赖不存在或已被删除' }
    }
    try {
      commitBatch(batchId, batch.auditIds, batch.state)
    } catch {
      pendingRecovery.value = hasPendingBatch()
      return {
        ok: false,
        error: pendingRecovery.value
          ? '写入失败，完整批次已暂存，可恢复重放（重放不新增审计）'
          : '写入失败，批次未能暂存',
      }
    }
    data.value = batch.state
    lastSavedAt.value = new Date().toISOString()
    return { ok: true }
  }

  const resolveDependencyConflict = (
    conflictId: string,
    resolution: 'retry' | 'discard',
  ): { ok: boolean; conflict?: DependencyConflict; error?: string } => {
    const conflict = data.value.dependencyConflicts.find((item) => item.id === conflictId)
    if (!conflict) return { ok: false, error: '冲突记录不存在' }

    if (resolution === 'discard') {
      data.value.dependencyConflicts = data.value.dependencyConflicts.filter(
        (item) => item.id !== conflictId,
      )
      appendAudit(
        'dependency',
        conflict.dependencyId,
        '放弃冲突草稿',
        `${conflict.dependencyName} 的${dependencyTransitionLabel(conflict.targetStatus, conflict.targetStatus)}草稿已放弃`,
      )
      persist()
      return { ok: true }
    }

    const dependency = data.value.dependencies.find(
      (item) => item.id === conflict.dependencyId,
    )
    if (!dependency) return { ok: false, error: '依赖不存在或已被删除' }
    // 以最新修订号为基准重新提交同一草稿；再次冲突时会生成新的冲突记录
    data.value.dependencyConflicts = data.value.dependencyConflicts.filter(
      (item) => item.id !== conflictId,
    )
    persist()
    return changeDependencyStatus({
      dependencyId: dependency.id,
      targetStatus: conflict.targetStatus,
      reason: conflict.reason,
      baseRevision: dependency.revision,
    })
  }

  const recoverPendingBatch = (): boolean => {
    if (!hasPendingBatch()) {
      pendingRecovery.value = false
      return false
    }
    // loadState 会整体重放暂存批次，批次内审计记录保持不变
    data.value = loadState()
    pendingRecovery.value = false
    lastSavedAt.value = new Date().toISOString()
    return true
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
    data.value = resetState()
    pendingRecovery.value = false
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
    pendingRecovery,
    dependencyConflicts,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    changeDependencyStatus,
    resolveDependencyConflict,
    recoverPendingBatch,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
