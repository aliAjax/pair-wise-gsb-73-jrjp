<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Tab from 'primevue/tab'
import TabList from 'primevue/tablist'
import TabPanel from 'primevue/tabpanel'
import TabPanels from 'primevue/tabpanels'
import Tabs from 'primevue/tabs'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import DataFlowDiagram from '@/components/DataFlowDiagram.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ArchitectureComponent,
  DataFlow,
  DependencyStatus,
  DependencyTransitionConflict,
  ExternalDependency,
  SystemBoundary,
  TrustZone,
} from '@/models/domain'
import { createId } from '@/services/repository'
import {
  computeDependencyTransition,
  DEPENDENCY_STATUS_LABELS,
} from '@/services/disposalChain'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const activeTab = ref('components')

const boundaryVisible = ref(false)
const componentVisible = ref(false)
const flowVisible = ref(false)
const dependencyVisible = ref(false)
const transitionVisible = ref(false)

const boundaryForm = reactive<SystemBoundary>({ ...store.data.boundary })
const componentForm = reactive<ArchitectureComponent>({
  id: '',
  name: '',
  type: 'service',
  zoneId: '',
  criticality: 'medium',
  owner: '',
  description: '',
})
const flowForm = reactive<DataFlow>({
  id: '',
  name: '',
  sourceId: '',
  targetId: '',
  protocol: 'HTTPS',
  dataClass: 'internal',
  crossesTrustBoundary: true,
  description: '',
  status: 'active',
})
const dependencyForm = reactive<ExternalDependency>({
  id: '',
  name: '',
  vendor: '',
  purpose: '',
  dataClass: 'internal',
  owner: '',
  status: 'active',
  vendorStatus: 'pending',
})

const transitionDependency = ref<ExternalDependency | null>(null)
const transitionTarget = ref<DependencyStatus>('active')
const transitionBaseStatus = ref<DependencyStatus>('active')
const transitionConflictMessage = ref('')

const componentTypes = [
  { label: '业务服务', value: 'service' },
  { label: '数据资产', value: 'asset' },
  { label: '数据存储', value: 'data_store' },
  { label: '安全网关', value: 'gateway' },
  { label: '客户端', value: 'client' },
]
const criticalities = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
]
const dataClasses = [
  { label: '公开', value: 'public' },
  { label: '内部', value: 'internal' },
  { label: '机密', value: 'confidential' },
  { label: '受限', value: 'restricted' },
]
const vendorStatuses = [
  { label: '已确认', value: 'confirmed' },
  { label: '待核', value: 'pending' },
]

const transitionPreview = computed(() => {
  if (!transitionDependency.value) return null
  return computeDependencyTransition(
    store.data,
    transitionDependency.value.id,
    transitionTarget.value,
    { batchId: 'preview', actor: '', now: '' },
  )
})

const resetComponentForm = (item?: ArchitectureComponent): void => {
  Object.assign(
    componentForm,
    item ?? {
      id: '',
      name: '',
      type: 'service',
      zoneId: store.data.zones[0]?.id ?? '',
      criticality: 'medium',
      owner: '',
      description: '',
    },
  )
  componentVisible.value = true
}

const resetFlowForm = (item?: DataFlow): void => {
  Object.assign(
    flowForm,
    item ?? {
      id: '',
      name: '',
      sourceId: store.data.components[0]?.id ?? '',
      targetId: store.data.components[1]?.id ?? '',
      protocol: 'HTTPS',
      dataClass: 'internal',
      crossesTrustBoundary: true,
      description: '',
      externalDependencyId: undefined,
      status: 'active' as const,
      statusNote: undefined,
      invalidatedByDependencyId: undefined,
    },
  )
  flowVisible.value = true
}

const resetDependencyForm = (item?: ExternalDependency): void => {
  Object.assign(
    dependencyForm,
    item ?? {
      id: '',
      name: '',
      vendor: '',
      purpose: '',
      dataClass: 'internal',
      owner: '',
      status: 'active',
      vendorStatus: 'pending',
    },
  )
  dependencyVisible.value = true
}

const saveBoundary = (): void => {
  if (!boundaryForm.name.trim() || !boundaryForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '边界名称与负责人不能为空', life: 3000 })
    return
  }
  store.updateBoundary({ ...boundaryForm })
  boundaryVisible.value = false
  toast.add({ severity: 'success', summary: '已保存', detail: '系统边界已更新', life: 2500 })
}

const saveComponent = (): void => {
  if (!componentForm.name.trim() || !componentForm.zoneId || !componentForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '名称、信任区和负责人不能为空', life: 3000 })
    return
  }
  store.saveEntity('components', {
    ...componentForm,
    id: componentForm.id || createId('cmp'),
  })
  componentVisible.value = false
  toast.add({ severity: 'success', summary: '组件已保存', detail: componentForm.name, life: 2500 })
}

const saveFlow = (): void => {
  if (!flowForm.name.trim() || !flowForm.sourceId || !flowForm.targetId) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '名称、源组件和目标组件不能为空', life: 3000 })
    return
  }
  if (flowForm.sourceId === flowForm.targetId) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '源组件与目标组件不能相同', life: 3000 })
    return
  }
  store.saveEntity('flows', {
    ...flowForm,
    id: flowForm.id || createId('flow'),
    externalDependencyId: flowForm.externalDependencyId || undefined,
  })
  flowVisible.value = false
  toast.add({ severity: 'success', summary: '数据流已保存', detail: flowForm.name, life: 2500 })
}

const saveDependency = (): void => {
  if (!dependencyForm.name.trim() || !dependencyForm.vendor.trim() || !dependencyForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '依赖、供应商和负责人不能为空', life: 3000 })
    return
  }
  const existing = store.data.dependencies.find((item) => item.id === dependencyForm.id)
  store.saveEntity('dependencies', {
    ...dependencyForm,
    id: dependencyForm.id || createId('dep'),
    // 生命周期状态只允许通过停服/续期处置链变更，普通编辑保留当前状态
    status: existing?.status ?? 'active',
  })
  dependencyVisible.value = false
  toast.add({ severity: 'success', summary: '外部依赖已保存', detail: dependencyForm.name, life: 2500 })
}

const openTransition = (dependency: ExternalDependency, target: DependencyStatus): void => {
  transitionDependency.value = dependency
  transitionTarget.value = target
  transitionBaseStatus.value = dependency.status
  transitionConflictMessage.value = ''
  transitionVisible.value = true
}

const confirmTransition = (): void => {
  const dependency = transitionDependency.value
  if (!dependency) return
  const outcome = store.applyDependencyTransition(
    dependency.id,
    transitionTarget.value,
    transitionBaseStatus.value,
  )
  if (outcome.ok) {
    transitionVisible.value = false
    toast.add({
      severity: 'success',
      summary: '处置链已联动',
      detail: `${dependency.name} 已调整为「${DEPENDENCY_STATUS_LABELS[transitionTarget.value]}」，数据流、威胁结论与缓解任务已重算`,
      life: 3500,
    })
    return
  }
  if (outcome.reason === 'conflict') {
    transitionConflictMessage.value =
      `另一窗口已先将该依赖调整为「${DEPENDENCY_STATUS_LABELS[outcome.conflict.currentStatus]}」，先到者生效。` +
      `当前草稿「${DEPENDENCY_STATUS_LABELS[outcome.conflict.draftStatus]}」已保留到冲突列表，可在确认后重新提交。`
    toast.add({ severity: 'warn', summary: '提交冲突', detail: '先到者已生效，草稿与冲突已保留', life: 4000 })
    return
  }
  if (outcome.reason === 'write_failed') {
    transitionVisible.value = false
    toast.add({
      severity: 'error',
      summary: '写入失败',
      detail: '已从完整批次回滚，批次已保留，可重放恢复',
      life: 4000,
    })
    return
  }
  transitionVisible.value = false
}

const resubmitConflict = (conflict: DependencyTransitionConflict): void => {
  const dependency = store.data.dependencies.find((item) => item.id === conflict.dependencyId)
  store.dismissDependencyConflict(conflict.id)
  if (dependency) openTransition(dependency, conflict.draftStatus)
}

const replayBatch = (): void => {
  if (store.replayPendingBatch()) {
    toast.add({ severity: 'success', summary: '批次已恢复', detail: '失败批次重放成功，审计未重复新增', life: 3000 })
  } else {
    toast.add({ severity: 'error', summary: '重放失败', detail: '写入仍然失败，完整批次继续保留', life: 3500 })
  }
}

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? id
const zoneName = (id: string): string =>
  store.data.zones.find((zone) => zone.id === id)?.name ?? id

const saveZone = (zone: TrustZone): void => {
  store.saveEntity('zones', zone)
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="模型基线"
      title="架构、边界与数据流"
      description="维护系统边界、信任区、资产组件、数据流和外部依赖，作为威胁分析的结构化输入。"
    />

    <section v-if="store.pendingBatch" class="chain-banner batch-banner">
      <i class="pi pi-replay"></i>
      <div>
        <strong>存在写入失败的处置批次</strong>
        <span>
          依赖状态变更为「{{ DEPENDENCY_STATUS_LABELS[store.pendingBatch.toStatus] }}」的完整批次未写入成功，
          已从失败点回滚，可重放恢复；重放不会新增审计记录。
        </span>
      </div>
      <div class="banner-actions">
        <Button label="重放恢复" icon="pi pi-replay" size="small" @click="replayBatch" />
        <Button
          label="放弃批次"
          size="small"
          severity="secondary"
          text
          @click="store.discardPendingBatch()"
        />
      </div>
    </section>

    <section
      v-for="conflict in store.dependencyConflicts"
      :key="conflict.id"
      class="chain-banner conflict-banner"
    >
      <i class="pi pi-exclamation-triangle"></i>
      <div>
        <strong>{{ conflict.dependencyName }} 的提交冲突</strong>
        <span>
          另一窗口已先提交为「{{ DEPENDENCY_STATUS_LABELS[conflict.currentStatus] }}」并生效；
          本窗口草稿「{{ DEPENDENCY_STATUS_LABELS[conflict.draftStatus] }}」未覆盖先到结果。
        </span>
      </div>
      <div class="banner-actions">
        <Button
          label="以草稿重新提交"
          icon="pi pi-send"
          size="small"
          outlined
          @click="resubmitConflict(conflict)"
        />
        <Button
          label="放弃草稿"
          size="small"
          severity="secondary"
          text
          @click="store.dismissDependencyConflict(conflict.id)"
        />
      </div>
    </section>

    <section class="boundary-strip">
      <div>
        <span>当前系统</span>
        <strong>{{ store.data.boundary.name }}</strong>
      </div>
      <div>
        <span>范围</span>
        <strong>{{ store.data.boundary.inScope }}</strong>
      </div>
      <div>
        <span>排除项</span>
        <strong>{{ store.data.boundary.outOfScope }}</strong>
      </div>
      <Button label="编辑边界" icon="pi pi-pencil" outlined @click="boundaryVisible = true" />
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">数据流图</h2>
        <span class="muted">{{ store.data.components.length }} 个组件，{{ store.data.flows.length }} 条流</span>
      </div>
      <DataFlowDiagram />
    </section>

    <Tabs v-model:value="activeTab">
      <TabList>
        <Tab value="components">组件与资产</Tab>
        <Tab value="zones">信任区</Tab>
        <Tab value="flows">数据流</Tab>
        <Tab value="dependencies">外部依赖</Tab>
      </TabList>
      <TabPanels>
        <TabPanel value="components">
          <div class="tab-toolbar">
            <div>
              <strong>架构组件</strong>
              <span>组件必须进入威胁分析范围，或明确记录豁免。</span>
            </div>
            <Button label="新增组件" icon="pi pi-plus" @click="resetComponentForm()" />
          </div>
          <DataTable :value="store.data.components" dataKey="id" size="small" stripedRows>
            <Column field="name" header="组件" />
            <Column header="类型" style="width: 120px">
              <template #body="{ data }">
                {{ componentTypes.find((item) => item.value === data.type)?.label }}
              </template>
            </Column>
            <Column header="信任区" style="width: 140px">
              <template #body="{ data }">{{ zoneName(data.zoneId) }}</template>
            </Column>
            <Column header="关键度" style="width: 100px">
              <template #body="{ data }">
                <StatusTag :value="data.criticality" kind="severity" />
              </template>
            </Column>
            <Column field="owner" header="负责人" style="width: 150px" />
            <Column header="操作" style="width: 150px">
              <template #body="{ data }">
                <div class="action-stack">
                  <Button
                    icon="pi pi-pencil"
                    label="编辑"
                    size="small"
                    text
                    @click="resetComponentForm(data)"
                  />
                  <Button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    text
                    aria-label="删除组件"
                    @click="store.removeEntity('components', data.id)"
                  />
                </div>
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <TabPanel value="zones">
          <div class="tab-toolbar">
            <div>
              <strong>信任区</strong>
              <span>跨区数据流默认提高威胁评审优先级。</span>
            </div>
          </div>
          <div class="zone-grid">
            <article v-for="zone in store.data.zones" :key="zone.id" class="zone-item">
              <div>
                <strong>{{ zone.name }}</strong>
                <span>{{ zone.level }}</span>
              </div>
              <p>{{ zone.description }}</p>
              <code>{{ zone.id }}</code>
              <Button
                label="模拟更新说明"
                size="small"
                text
                @click="saveZone({ ...zone, description: `${zone.description} 已复核。` })"
              />
            </article>
          </div>
        </TabPanel>

        <TabPanel value="flows">
          <div class="tab-toolbar">
            <div>
              <strong>数据流清单</strong>
              <span>记录协议、数据级别与是否跨信任区。</span>
            </div>
            <Button label="新增数据流" icon="pi pi-plus" @click="resetFlowForm()" />
          </div>
          <DataTable :value="store.data.flows" dataKey="id" size="small" stripedRows>
            <Column field="name" header="数据流">
              <template #body="{ data }">
                <div class="flow-name-cell">
                  <span>{{ data.name }}</span>
                  <small v-if="data.statusNote" class="flow-note">{{ data.statusNote }}</small>
                </div>
              </template>
            </Column>
            <Column header="源 → 目标">
              <template #body="{ data }">
                {{ componentName(data.sourceId) }} → {{ componentName(data.targetId) }}
              </template>
            </Column>
            <Column field="protocol" header="协议" style="width: 130px" />
            <Column header="数据级别" style="width: 110px" />
            <Column header="跨信任区" style="width: 100px">
              <template #body="{ data }">
                <StatusTag :value="data.crossesTrustBoundary ? 'high' : 'low'" />
              </template>
            </Column>
            <Column header="状态" style="width: 100px">
              <template #body="{ data }">
                <StatusTag :value="data.status" kind="status" />
              </template>
            </Column>
            <Column header="操作" style="width: 150px">
              <template #body="{ data }">
                <Button icon="pi pi-pencil" label="编辑" size="small" text @click="resetFlowForm(data)" />
                <Button
                  icon="pi pi-trash"
                  size="small"
                  severity="danger"
                  text
                  aria-label="删除数据流"
                  @click="store.removeEntity('flows', data.id)"
                />
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <TabPanel value="dependencies">
          <div class="tab-toolbar">
            <div>
              <strong>外部依赖</strong>
              <span>外部服务需登记数据级别、供应商与责任团队。</span>
            </div>
            <Button label="新增依赖" icon="pi pi-plus" @click="resetDependencyForm()" />
          </div>
          <DataTable :value="store.data.dependencies" dataKey="id" size="small" stripedRows>
            <Column field="name" header="依赖" />
            <Column field="vendor" header="供应商" />
            <Column field="purpose" header="用途" />
            <Column field="dataClass" header="数据级别" style="width: 110px" />
            <Column field="owner" header="负责人" style="width: 140px" />
            <Column header="状态" style="width: 105px">
              <template #body="{ data }">
                <StatusTag :value="data.status" />
              </template>
            </Column>
            <Column header="供应商状态" style="width: 110px">
              <template #body="{ data }">
                <StatusTag :value="data.vendorStatus" />
              </template>
            </Column>
            <Column header="操作" style="width: 300px">
              <template #body="{ data }">
                <div class="action-stack">
                  <Button
                    v-if="data.status !== 'retired'"
                    icon="pi pi-power-off"
                    label="停服"
                    size="small"
                    severity="danger"
                    text
                    @click="openTransition(data, 'retired')"
                  />
                  <Button
                    v-if="data.status === 'review_due'"
                    icon="pi pi-refresh"
                    label="续期"
                    size="small"
                    severity="success"
                    text
                    @click="openTransition(data, 'active')"
                  />
                  <Button
                    v-if="data.status === 'retired'"
                    icon="pi pi-undo"
                    label="恢复"
                    size="small"
                    severity="success"
                    text
                    @click="openTransition(data, 'active')"
                  />
                  <Button
                    icon="pi pi-pencil"
                    label="编辑"
                    size="small"
                    text
                    @click="resetDependencyForm(data)"
                  />
                  <Button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    text
                    aria-label="删除依赖"
                    @click="store.removeEntity('dependencies', data.id)"
                  />
                </div>
              </template>
            </Column>
          </DataTable>
        </TabPanel>
      </TabPanels>
    </Tabs>

    <Dialog v-model:visible="boundaryVisible" header="编辑系统边界" modal :style="{ width: '680px' }">
      <div class="editor-form">
        <div class="field">
          <label>系统名称</label>
          <InputText v-model="boundaryForm.name" />
        </div>
        <div class="field">
          <label>责任团队</label>
          <InputText v-model="boundaryForm.owner" />
        </div>
        <div class="field field-wide">
          <label>系统说明</label>
          <Textarea v-model="boundaryForm.description" rows="3" />
        </div>
        <div class="field field-wide">
          <label>建模范围内</label>
          <Textarea v-model="boundaryForm.inScope" rows="3" />
        </div>
        <div class="field field-wide">
          <label>明确排除</label>
          <Textarea v-model="boundaryForm.outOfScope" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="boundaryVisible = false" />
        <Button label="保存边界" icon="pi pi-check" @click="saveBoundary" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="componentVisible"
      :header="componentForm.id ? '编辑组件' : '新增组件'"
      modal
      :style="{ width: '680px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>组件名称</label>
          <InputText v-model="componentForm.name" />
        </div>
        <div class="field">
          <label>组件类型</label>
          <Select v-model="componentForm.type" :options="componentTypes" option-label="label" option-value="value" />
        </div>
        <div class="field">
          <label>信任区</label>
          <Select
            v-model="componentForm.zoneId"
            :options="store.data.zones"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>关键度</label>
          <Select
            v-model="componentForm.criticality"
            :options="criticalities"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="componentForm.owner" />
        </div>
        <div class="field field-wide">
          <label>说明</label>
          <Textarea v-model="componentForm.description" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="componentVisible = false" />
        <Button label="保存组件" icon="pi pi-check" @click="saveComponent" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="flowVisible"
      :header="flowForm.id ? '编辑数据流' : '新增数据流'"
      modal
      :style="{ width: '720px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>数据流名称</label>
          <InputText v-model="flowForm.name" />
        </div>
        <div class="field">
          <label>源组件</label>
          <Select
            v-model="flowForm.sourceId"
            :options="store.data.components"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>目标组件</label>
          <Select
            v-model="flowForm.targetId"
            :options="store.data.components"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>协议</label>
          <InputText v-model="flowForm.protocol" />
        </div>
        <div class="field">
          <label>数据级别</label>
          <Select
            v-model="flowForm.dataClass"
            :options="dataClasses"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>关联外部依赖</label>
          <Select
            v-model="flowForm.externalDependencyId"
            :options="store.data.dependencies"
            option-label="name"
            option-value="id"
            placeholder="不关联"
            show-clear
          />
        </div>
        <div class="field field-wide">
          <label>说明</label>
          <Textarea v-model="flowForm.description" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="flowVisible = false" />
        <Button label="保存数据流" icon="pi pi-check" @click="saveFlow" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="dependencyVisible"
      :header="dependencyForm.id ? '编辑依赖' : '新增依赖'"
      modal
      :style="{ width: '680px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>依赖名称</label>
          <InputText v-model="dependencyForm.name" />
        </div>
        <div class="field">
          <label>供应商</label>
          <InputText v-model="dependencyForm.vendor" />
        </div>
        <div class="field">
          <label>数据级别</label>
          <Select
            v-model="dependencyForm.dataClass"
            :options="dataClasses"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="dependencyForm.owner" />
        </div>
        <div class="field">
          <label>供应商状态</label>
          <Select
            v-model="dependencyForm.vendorStatus"
            :options="vendorStatuses"
            option-label="label"
            option-value="value"
          />
          <small class="muted">待核状态下，关联威胁不能批准会签。</small>
        </div>
        <div class="field field-wide">
          <label>用途</label>
          <Textarea v-model="dependencyForm.purpose" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="dependencyVisible = false" />
        <Button label="保存依赖" icon="pi pi-check" @click="saveDependency" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="transitionVisible"
      :header="`${transitionDependency?.name ?? ''}：${DEPENDENCY_STATUS_LABELS[transitionTarget]}确认`"
      modal
      :style="{ width: '640px' }"
    >
      <div v-if="transitionDependency" class="transition-body">
        <p class="transition-lead">
          依赖状态将由「{{ DEPENDENCY_STATUS_LABELS[transitionBaseStatus] }}」调整为「{{
            DEPENDENCY_STATUS_LABELS[transitionTarget]
          }}」，提交后处置链立即联动：
        </p>
        <ul class="transition-effects">
          <li>
            数据流：{{ transitionPreview?.flows.length ?? 0 }} 条{{
              transitionTarget === 'retired' ? '立即失效并重算' : '重算恢复'
            }}
          </li>
          <li>威胁结论：{{ transitionPreview?.threats.length ?? 0 }} 条回到会签流程重新确认</li>
          <li>缓解任务：{{ transitionPreview?.mitigations.length ?? 0 }} 条未开始任务回到待重排</li>
          <li>已完成任务保留原完成依据，不受本次变更影响</li>
        </ul>
        <p v-if="transitionConflictMessage" class="transition-conflict">
          <i class="pi pi-exclamation-triangle"></i>
          {{ transitionConflictMessage }}
        </p>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="transitionVisible = false" />
        <Button
          :label="`确认${DEPENDENCY_STATUS_LABELS[transitionTarget]}`"
          icon="pi pi-check"
          :severity="transitionTarget === 'retired' ? 'danger' : 'success'"
          @click="confirmTransition"
        />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.boundary-strip {
  display: grid;
  grid-template-columns: 0.8fr 1.2fr 1.2fr auto;
  align-items: center;
  gap: 18px;
  padding: 16px;
  border: 1px solid #dce2ea;
  border-left: 4px solid #426f9e;
  border-radius: 6px;
  background: #fff;
}

.chain-banner {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  padding: 14px 16px;
  border-radius: 6px;
}

.chain-banner > i {
  margin-top: 2px;
}

.chain-banner > div:nth-child(2) {
  display: grid;
  gap: 4px;
  flex: 1;
}

.chain-banner span {
  font-size: 12px;
}

.batch-banner {
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  background: #fffaf0;
}

.batch-banner > i {
  color: #b45309;
}

.batch-banner span {
  color: #7b5d2c;
}

.conflict-banner {
  border: 1px solid #f1b7b0;
  border-left: 4px solid #c64b39;
  background: #fff6f5;
}

.conflict-banner > i {
  color: #b33627;
}

.conflict-banner span {
  color: #8a4238;
}

.banner-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.flow-name-cell {
  display: grid;
  gap: 3px;
}

.flow-note {
  color: #a05a00;
  font-size: 11px;
}

.transition-body {
  display: grid;
  gap: 14px;
}

.transition-lead {
  margin: 0;
  color: #414d61;
  font-size: 13px;
  line-height: 1.6;
}

.transition-effects {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 12px 14px 12px 30px;
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  background: #f8fafc;
  color: #4c586d;
  font-size: 12px;
}

.transition-conflict {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin: 0;
  padding: 10px 12px;
  border: 1px solid #f1b7b0;
  border-radius: 6px;
  background: #fff6f5;
  color: #8a4238;
  font-size: 12px;
  line-height: 1.55;
}

.transition-conflict i {
  margin-top: 1px;
}

.boundary-strip > div {
  display: grid;
  gap: 6px;
  min-width: 0;
}

.boundary-strip span {
  color: #727d90;
  font-size: 11px;
}

.boundary-strip strong {
  color: #273247;
  font-size: 13px;
  line-height: 1.45;
}

.tab-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
}

.tab-toolbar > div {
  display: grid;
  gap: 5px;
}

.tab-toolbar span {
  color: #707b8e;
  font-size: 12px;
}

.zone-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  padding-bottom: 16px;
}

.zone-item {
  display: flex;
  flex-direction: column;
  gap: 11px;
  min-height: 172px;
  padding: 15px;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #fff;
}

.zone-item > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.zone-item > div span {
  color: #667189;
  font-size: 11px;
  text-transform: uppercase;
}

.zone-item p {
  flex: 1;
  margin: 0;
  color: #5f6b80;
  font-size: 12px;
  line-height: 1.55;
}

.zone-item code {
  color: #8791a3;
  font-size: 11px;
}

.zone-item :deep(.p-button) {
  align-self: flex-start;
  padding-left: 0;
}
</style>
