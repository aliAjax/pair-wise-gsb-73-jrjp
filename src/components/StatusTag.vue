<script setup lang="ts">
import { computed } from 'vue'
import Tag from 'primevue/tag'

const props = defineProps<{
  value: string
  kind?: 'severity' | 'status' | 'review'
}>()

const labels: Record<string, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  open: '开放',
  mitigating: '处置中',
  mitigated: '已缓解',
  accepted: '已接受',
  closed: '已关闭',
  effective: '有效',
  degraded: '降级',
  failed: '失效',
  planned: '计划中',
  draft: '草稿',
  in_review: '审核中',
  approved: '已通过',
  rejected: '已驳回',
  todo: '待处理',
  in_progress: '进行中',
  verifying: '验证中',
  done: '已完成',
  reschedule: '待重排',
  active: '有效',
  review_due: '待续期',
  retired: '已停服',
  invalid: '已失效',
  pending: '待核',
  confirmed: '已确认',
}

const palette = computed(() => {
  const severity: Record<string, string> = {
    critical: 'danger',
    failed: 'danger',
    rejected: 'danger',
    retired: 'danger',
    invalid: 'danger',
    high: 'warn',
    degraded: 'warn',
    in_review: 'warn',
    medium: 'warn',
    review_due: 'warn',
    reschedule: 'warn',
    pending: 'warn',
    mitigating: 'info',
    in_progress: 'info',
    verifying: 'info',
    low: 'success',
    effective: 'success',
    approved: 'success',
    mitigated: 'success',
    closed: 'success',
    done: 'success',
    active: 'success',
    confirmed: 'success',
  }
  return severity[props.value] ?? 'secondary'
})
</script>

<template>
  <Tag :value="labels[value] ?? value" :severity="palette" />
</template>
