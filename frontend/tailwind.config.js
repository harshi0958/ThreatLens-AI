/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        night: '#07131f',
        panel: '#0f1f2d',
        accent: '#4ea1ff',
        danger: '#ff5b65',
        warn: '#f7b955',
        success: '#42d392',
      },
      boxShadow: {
        panel: '0 18px 40px rgba(15, 23, 42, 0.35)',
      },
    },
  },
  plugins: [],
}
