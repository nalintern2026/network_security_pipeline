/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#222831',
        surface: '#393E46',
        primary: '#00ADB5',
        'text-primary': '#EEEEEE',
        'text-muted': '#B0B5BA',
        success: '#22C55E',
        warning: '#F59E0B',
        danger: '#EF4444',
        info: '#3B82F6',
        // Legacy dark names mapped to new palette for minimal class changes
        dark: {
          900: '#222831',
          800: '#393E46',
          700: '#393E46',
          600: '#393E46',
          500: '#393E46',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      fontSize: {
        'h1': ['28px', { lineHeight: '1.3' }],
        'h2': ['22px', { lineHeight: '1.35' }],
        'body': ['16px', { lineHeight: '1.5' }],
        'small': ['13px', { lineHeight: '1.45' }],
      },
      spacing: {
        '18': '72px',
        '22': '88px',
      },
      animation: {
        'slide-up': 'slideUp 0.4s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
      },
      keyframes: {
        slideUp: {
          '0%': { transform: 'translateY(16px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
