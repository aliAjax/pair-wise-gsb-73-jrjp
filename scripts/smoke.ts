/* 处置链冒烟测试：使用 esbuild 打包后在 node 中运行（见 package.json 注释或手动命令）。 */
import { createPinia, setActivePinia } from 'pinia'

// --- localStorage 内存实现 ---
const backing = new Map<string, string>()
const localStorageShim = {
  getItem: (key: string): string | null => (backing.has(key) ? backing.get(key)! : null),
  setItem: (key: string, value: string): void => {
    backing.set(key, String(value))
  },
  removeItem: (key: string): void => {
    backing.delete(key)
  },
}
;(globalThis as Record<string, unknown>).localStorage = localStorageShim

let passed = 0
let failed = 0
const assert = (condition: boolean, message: string): void => {
  if (condition) {
    passed += 1
    console.log(`  ✓ ${message}`)
  } else {
    failed += 1
    console.error(`  ✗ ${message}`)
  }
}

const main = async (): Promise<void> => {
  const { useThreatModelStore } = await import('@/stores/threatModel')
  const { loadState, STORAGE_KEY } = await import('@/services/repository')
  const { createSeedState } = await import('@/models/seed')
  const { applyDisposalBatch, computeDependencyTransition } = await import(
    '@/services/disposalChain'
  )

  // ---------- 1. 旧数据迁移：缺少供应商状态先待核 ----------
  console.log('\n[1] 旧数据迁移')
  const legacy = createSeedState() as unknown as Record<string, unknown>
  ;(legacy.dependencies as Record<string, unknown>[]).forEach((dep) => {
    delete dep.vendorStatus
  })
  ;(legacy.flows as Record<string, unknown>[]).forEach((flow) => {
    delete flow.status
  })
  delete legacy.stamp
  localStorageShim.setItem(STORAGE_KEY, JSON.stringify(legacy))
  const migrated = loadState()
  assert(
    migrated.dependencies.every((dep) => dep.vendorStatus === 'pending'),
    '缺少供应商状态的依赖全部标记为待核',
  )
  assert(
    migrated.flows.every((flow) => flow.status === 'active'),
    '缺少状态的数据流迁移为有效',
  )
  assert(typeof migrated.stamp === 'string' && migrated.stamp.length > 0, '补发并发戳记')
  const persistedRaw = JSON.parse(localStorageShim.getItem(STORAGE_KEY)!)
  assert(persistedRaw.dependencies[0].vendorStatus === 'pending', '迁移结果已写回持久层')

  // ---------- 2. 处置链：停服联动 ----------
  console.log('\n[2] 停服处置链')
  localStorageShim.removeItem(STORAGE_KEY)
  setActivePinia(createPinia())
  const store = useThreatModelStore()

  const outcome = store.applyDependencyTransition('dep-02', 'retired', 'review_due')
  assert(outcome.ok, '停服提交成功')

  const flow04 = store.data.flows.find((flow) => flow.id === 'flow-04')!
  assert(flow04.status === 'invalid', '关联数据流 flow-04 立即失效')
  assert(flow04.invalidatedByDependencyId === 'dep-02', '失效数据流记录来源依赖')
  const flow05 = store.data.flows.find((flow) => flow.id === 'flow-05')!
  assert(flow05.status === 'active', '未关联的数据流 flow-05 不受影响')

  const thr02 = store.data.threats.find((threat) => threat.id === 'thr-02')!
  assert(thr02.reviewStatus === 'in_review', '已通过的威胁结论回到会签')
  assert(thr02.revision === 3, '威胁修订号递进，旧会签意见不再计入')

  const mit04 = store.data.mitigations.find((task) => task.id === 'mit-04')!
  assert(mit04.status === 'reschedule', '未开始的缓解任务回到待重排')
  const mit03 = store.data.mitigations.find((task) => task.id === 'mit-03')!
  assert(mit03.status === 'verifying', '已开始的任务不回到待重排')

  assert(
    store.data.audit.some((event) => event.action === '依赖状态变更'),
    '处置链写入审计记录',
  )
  assert(
    store.issues.some((issue) => issue.kind === 'flow_invalidated'),
    '失效数据流进入校验问题',
  )

  // ---------- 3. 已完成结果保留原依据 ----------
  console.log('\n[3] 已完成结果保留原依据')
  store.updateMitigationStatus('mit-04', 'done')
  const doneTask = store.data.mitigations.find((task) => task.id === 'mit-04')!
  assert(Boolean(doneTask.completedAt) && Boolean(doneTask.completedBasis), '完成任务记录完成依据')
  assert(
    doneTask.completedBasis!.includes('对象归档服务=已停服'),
    '完成依据包含当时依赖状态',
  )
  const basisBefore = doneTask.completedBasis

  const renewOutcome = store.applyDependencyTransition('dep-02', 'active', 'retired')
  assert(renewOutcome.ok, '续期提交成功')
  const flow04After = store.data.flows.find((flow) => flow.id === 'flow-04')!
  assert(flow04After.status === 'active', '续期后数据流重算恢复')
  assert(flow04After.invalidatedByDependencyId === undefined, '失效来源标记已清除')
  const mit04After = store.data.mitigations.find((task) => task.id === 'mit-04')!
  assert(mit04After.status === 'done', '续期不改变已完成任务状态')
  assert(mit04After.completedBasis === basisBefore, '已完成结果保留原依据')

  // ---------- 4. 两窗口并发：先到者生效 ----------
  console.log('\n[4] 并发冲突')
  const persisted = JSON.parse(localStorageShim.getItem(STORAGE_KEY)!)
  persisted.dependencies.find((dep: { id: string }) => dep.id === 'dep-01').status = 'retired'
  persisted.stamp = 'other-window-stamp'
  localStorageShim.setItem(STORAGE_KEY, JSON.stringify(persisted))

  const conflictOutcome = store.applyDependencyTransition('dep-01', 'review_due', 'active')
  assert(!conflictOutcome.ok && conflictOutcome.reason === 'conflict', '后到提交被判定为冲突')
  const dep01 = store.data.dependencies.find((dep) => dep.id === 'dep-01')!
  assert(dep01.status === 'retired', '先到者的停服结果生效，未被覆盖')
  assert(store.dependencyConflicts.length === 1, '冲突已保留')
  assert(
    store.dependencyConflicts[0].draftStatus === 'review_due',
    '后到者的草稿状态保留在冲突记录中',
  )
  store.dismissDependencyConflict(store.dependencyConflicts[0].id)
  assert(store.dependencyConflicts.length === 0, '冲突可处理后清除')

  // 无关变更可合并：另一窗口只改了 dep-03 名称
  const persisted2 = JSON.parse(localStorageShim.getItem(STORAGE_KEY)!)
  persisted2.dependencies.find((dep: { id: string }) => dep.id === 'dep-03').name = '伙伴归因接口V2'
  persisted2.stamp = 'other-window-stamp-2'
  localStorageShim.setItem(STORAGE_KEY, JSON.stringify(persisted2))
  const mergeOutcome = store.applyDependencyTransition('dep-01', 'active', 'retired')
  assert(mergeOutcome.ok, '另一窗口的无关变更不阻塞本依赖提交')
  assert(
    store.data.dependencies.find((dep) => dep.id === 'dep-03')!.name === '伙伴归因接口V2',
    '无关变更被合并保留',
  )

  // ---------- 5. 写入失败：完整批次恢复，重放不新增审计 ----------
  console.log('\n[5] 写入失败与重放')
  const originalSetItem = localStorageShim.setItem
  localStorageShim.setItem = (key: string, value: string): void => {
    if (key === STORAGE_KEY) throw new Error('QuotaExceededError')
    originalSetItem(key, value)
  }
  const failOutcome = store.applyDependencyTransition('dep-03', 'retired', 'active')
  assert(!failOutcome.ok && failOutcome.reason === 'write_failed', '写入失败被捕获')
  const dep03AfterFail = store.data.dependencies.find((dep) => dep.id === 'dep-03')!
  assert(dep03AfterFail.status === 'active', '失败后内存状态从完整批次回滚')
  assert(store.pendingBatch !== null, '完整批次已保留待重放')
  const auditCountAfterFail = store.data.audit.length

  localStorageShim.setItem = originalSetItem
  const replayed = store.replayPendingBatch()
  assert(replayed, '恢复写入后重放成功')
  assert(store.pendingBatch === null, '重放成功后批次清空')
  const dep03AfterReplay = store.data.dependencies.find((dep) => dep.id === 'dep-03')!
  assert(dep03AfterReplay.status === 'retired', '重放后依赖状态生效')
  const flow05AfterReplay = store.data.flows.find((flow) => flow.id === 'flow-05')!
  assert(flow05AfterReplay.status === 'invalid', '重放后关联数据流失效')
  const auditIds = store.data.audit.map((event) => event.id)
  assert(new Set(auditIds).size === auditIds.length, '审计记录无重复 ID')
  assert(
    store.data.audit.length > auditCountAfterFail,
    '重放补齐了批次自身的审计记录',
  )

  // 同一批次再次应用也不新增审计（幂等）
  const batch = computeDependencyTransition(store.data, 'dep-01', 'retired', {
    batchId: 'batch-idem',
    actor: '测试',
    now: new Date().toISOString(),
  })!
  applyDisposalBatch(store.data, batch)
  const auditCountOnce = store.data.audit.length
  applyDisposalBatch(store.data, batch)
  assert(store.data.audit.length === auditCountOnce, '同一批次重复应用不新增审计')

  // ---------- 6. 待核依赖阻断会签批准 ----------
  console.log('\n[6] 供应商待核阻断会签')
  const dep02 = store.data.dependencies.find((dep) => dep.id === 'dep-02')!
  store.saveEntity('dependencies', { ...dep02, vendorStatus: 'pending' as const })
  assert(
    store.issues.some((issue) => issue.kind === 'dependency_vendor_pending'),
    '待核依赖进入校验问题',
  )
  const blocked = store.submitDecision('thr-02', 'security', 'approved', '王岚', '同意')
  assert(!blocked.ok, '待核状态下批准会签被拦截')
  const thr02After = store.data.threats.find((threat) => threat.id === 'thr-02')!
  assert(thr02After.reviewStatus !== 'approved', '威胁结论未被批准')
  const allowedDecision = store.submitDecision('thr-02', 'security', 'evidence_required', '王岚', '先补证')
  assert(allowedDecision.ok, '非批准类意见不受待核限制')
  store.saveEntity('dependencies', { ...dep02, vendorStatus: 'confirmed' as const })
  const unblocked = store.submitDecision('thr-02', 'security', 'approved', '王岚', '供应商已确认，同意')
  assert(unblocked.ok, '补齐供应商状态后可以批准会签')

  console.log(`\n结果：${passed} 通过，${failed} 失败`)
  if (failed > 0) process.exit(1)
}

void main()
