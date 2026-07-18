import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#09090B",
        surface: "#111216",
        surface2: "#16161B",
        border: "rgba(255,255,255,0.08)",
        primary: {
          DEFAULT: "#4F8CFF",
          foreground: "#ffffff",
        },
        success: "#16C47F",
        warning: "#F4B740",
        danger: "#FF5F6D",
        muted: {
          DEFAULT: "#6B6B76",
          foreground: "#9A9AA5",
        },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      borderRadius: {
        xl: "14px",
        "2xl": "18px",
        "3xl": "24px",
      },
      boxShadow: {
        soft: "0 1px 2px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.25)",
        glow: "0 0 40px rgba(79,140,255,0.25)",
        "glow-danger": "0 0 40px rgba(255,95,109,0.25)",
        "glow-success": "0 0 40px rgba(22,196,127,0.2)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-soft": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
        "drift-1": {
          "0%, 100%": { transform: "translate(0,0) scale(1)" },
          "50%": { transform: "translate(40px,-30px) scale(1.08)" },
        },
        "drift-2": {
          "0%, 100%": { transform: "translate(0,0) scale(1)" },
          "50%": { transform: "translate(-30px,40px) scale(0.95)" },
        },
        "grid-pan": {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "60px 60px" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.4s ease-out",
        "slide-up": "slide-up 0.5s cubic-bezier(0.16, 1, 0.3, 1)",
        "pulse-soft": "pulse-soft 2s ease-in-out infinite",
        "drift-1": "drift-1 22s ease-in-out infinite",
        "drift-2": "drift-2 28s ease-in-out infinite",
        "grid-pan": "grid-pan 8s linear infinite",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
