/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0d10",
        panel: "#121519",
        border: "#1e242c",
        muted: "#8b95a3",
        allow: "#3ecf8e",
        deny: "#ef4444",
        monitor: "#f5a623",
        accent: "#60a5fa",
        chip: "#1a1f27",
      },
      fontFamily: {
        mono: ["ui-monospace", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
