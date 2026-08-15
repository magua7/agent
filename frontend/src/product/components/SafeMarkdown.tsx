import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

function safeLink(href?: string): string | undefined {
  if (!href) return undefined
  const normalized = href.trim().toLowerCase()
  if (normalized.startsWith("https://") || normalized.startsWith("http://") || normalized.startsWith("mailto:") || href.startsWith("#") || href.startsWith("/")) {
    return href
  }
  return undefined
}

export function SafeMarkdown({ content }: { content: string }) {
  return (
    <div className="markdown-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => {
            const safeHref = safeLink(href)
            return safeHref
              ? <a href={safeHref} target="_blank" rel="noopener noreferrer">{children}</a>
              : <span>{children}</span>
          },
          img: ({ alt }) => <span className="text-slate-500">[图片：{alt || "未命名"}]</span>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}

