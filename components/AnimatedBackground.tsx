"use client";

import { motion } from "framer-motion";
import { useMemo } from "react";

export function AnimatedBackground() {
  const nodes = useMemo(
    () =>
      Array.from({ length: 18 }, () => ({
        x: Math.random() * 100,
        y: Math.random() * 100,
        size: Math.random() * 2 + 1,
        duration: Math.random() * 8 + 8,
        delay: Math.random() * 6,
      })),
    []
  );

  return (
    <div className="fixed inset-0 -z-10 overflow-hidden bg-background pointer-events-none">
      {/* Animated grid */}
      <div className="absolute inset-0 grid-bg animate-grid-pan opacity-60" />

      {/* Soft drifting blobs */}
      <div
        className="absolute -top-32 -left-32 h-[480px] w-[480px] rounded-full blur-[120px] opacity-25 animate-drift-1"
        style={{
          background:
            "radial-gradient(circle at center, rgba(79,140,255,0.55) 0%, transparent 70%)",
        }}
      />
      <div
        className="absolute top-1/3 -right-40 h-[520px] w-[520px] rounded-full blur-[140px] opacity-20 animate-drift-2"
        style={{
          background:
            "radial-gradient(circle at center, rgba(255,95,109,0.45) 0%, transparent 70%)",
        }}
      />
      <div
        className="absolute -bottom-40 left-1/3 h-[460px] w-[460px] rounded-full blur-[130px] opacity-15 animate-drift-1"
        style={{
          background:
            "radial-gradient(circle at center, rgba(22,196,127,0.4) 0%, transparent 70%)",
          animationDelay: "6s",
        }}
      />

      {/* Tiny moving nodes */}
      <svg className="absolute inset-0 h-full w-full" preserveAspectRatio="none">
        {nodes.map((n, i) => (
          <motion.circle
            key={i}
            cx={`${n.x}%`}
            cy={`${n.y}%`}
            r={n.size}
            fill="rgba(255,255,255,0.35)"
            initial={{ opacity: 0 }}
            animate={{
              opacity: [0, 0.6, 0],
              cy: [`${n.y}%`, `${n.y - 8}%`, `${n.y}%`],
            }}
            transition={{
              duration: n.duration,
              delay: n.delay,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        ))}
      </svg>

      {/* Vignette to focus center */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 60% 50% at 50% 50%, transparent 0%, rgba(9,9,11,0.4) 80%, rgba(9,9,11,0.9) 100%)",
        }}
      />
    </div>
  );
}
