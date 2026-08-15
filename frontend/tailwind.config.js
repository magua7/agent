/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        headline: ['Aldrich', 'Orbitron', 'Segoe UI', 'system-ui', 'sans-serif'],
        body: ['Segoe UI', 'system-ui', '-apple-system', 'sans-serif'],
      },
      maxWidth: {
        'app-shell': '1380px',
        'content-column': '1120px',
        'chat-column': '1040px',
      },
      boxShadow: {
        shell: '0 28px 90px -46px rgba(15, 23, 42, 0.24)',
        panel: '0 20px 60px -36px rgba(14, 165, 233, 0.18)',
        'panel-dark': '0 30px 90px -54px rgba(2, 12, 27, 0.9)',
      },
      colors: {
        risk0: { DEFAULT: '#22c55e', bg: '#166534' },
        risk1: { DEFAULT: '#06b6d4', bg: '#155e75' },
        risk2: { DEFAULT: '#eab308', bg: '#854d0e' },
        risk3: { DEFAULT: '#ef4444', bg: '#991b1b' },
        cyber: {
          50: '#f3fbff',
          100: '#e4f7ff',
          200: '#b9ecff',
          300: '#77dcff',
          400: '#29c9ff',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0b5f8a',
          800: '#0f3f60',
          900: '#0a2037',
        },
      },
    },
  },
  plugins: [],
}
