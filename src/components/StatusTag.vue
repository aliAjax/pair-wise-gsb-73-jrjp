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
  reschedule: '待重排',
  in_progress: '进行中',
  verifying: '验证中',
  done: '已完成',
  active: '在用',
  review_due: '待复核',
  retired: '已停服',
  pending_verification: '待核',
  invalidated: '已失效',
}

const palette = computed(() => {
  const severity: Record<string, string> = {
    critical: 'danger',
    failed: 'danger',
    rejected: 'danger',
    invalidated: 'danger',
    high: 'warn',
    degraded: 'warn',
    in_review: 'warn',
    medium: 'warn',
    review_due: 'warn',
    pending_verification: 'warn',
    reschedule: 'warn',
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
    retired: 'secondary',
  }
  return severity[props.value] ?? 'secondary'
})
</script>

<template>
  <Tag :value="labels[value] ?? value" :severity="palette" />
</template>
