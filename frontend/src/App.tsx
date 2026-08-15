import { SecGoApp } from "./product/SecGoApp"
import { ProductErrorBoundary } from "./product/components/ProductErrorBoundary"

export default function App() {
  return (
    <ProductErrorBoundary>
      <SecGoApp />
    </ProductErrorBoundary>
  )
}
