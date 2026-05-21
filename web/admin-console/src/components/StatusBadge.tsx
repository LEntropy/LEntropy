import { clsx } from 'clsx'

type Status = 'allowed' | 'blocked' | 'quarantine' | 'pending'

const labels: Record<Status, string> = {
  allowed: '허용',
  blocked: '차단',
  quarantine: '격리',
  pending: '대기',
}

const styles: Record<Status, string> = {
  allowed: 'bg-green-100 text-green-800',
  blocked: 'bg-red-100 text-red-800',
  quarantine: 'bg-yellow-100 text-yellow-800',
  pending: 'bg-gray-100 text-gray-700',
}

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', styles[status])}>
      {labels[status]}
    </span>
  )
}
