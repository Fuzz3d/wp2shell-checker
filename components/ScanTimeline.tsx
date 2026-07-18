"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Check, Loader2, Circle } from "lucide-react";
import { cn } from "@/lib/utils";

export type StepStatus = "pending" | "active" | "done";

export interface TimelineStep {
  id: string;
  label: string;
  status: StepStatus;
}

export function ScanTimeline({ steps }: { steps: TimelineStep[] }) {
  return (
    <div className="relative mt-8 pl-1">
      <div className="absolute left-[7px] top-2 bottom-2 w-px bg-white/8" />
      <ul className="space-y-4">
        {steps.map((step, i) => (
          <motion.li
            key={step.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.08, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
            className="relative flex items-center gap-3"
          >
            <div className="relative z-10 flex h-4 w-4 items-center justify-center">
              <AnimatePresence mode="wait">
                {step.status === "done" && (
                  <motion.span
                    key="done"
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0, opacity: 0 }}
                    transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                    className="flex h-4 w-4 items-center justify-center rounded-full bg-success/15"
                  >
                    <Check className="h-3 w-3 text-success" strokeWidth={3} />
                  </motion.span>
                )}
                {step.status === "active" && (
                  <motion.span
                    key="active"
                    initial={{ scale: 0.6, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.6, opacity: 0 }}
                    className="flex h-4 w-4 items-center justify-center"
                  >
                    <Loader2 className="h-3.5 w-3.5 text-primary animate-spin" />
                  </motion.span>
                )}
                {step.status === "pending" && (
                  <motion.span
                    key="pending"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="flex h-4 w-4 items-center justify-center"
                  >
                    <Circle className="h-2 w-2 text-white/25 fill-white/10" />
                  </motion.span>
                )}
              </AnimatePresence>
            </div>

            <span
              className={cn(
                "text-sm font-mono transition-colors duration-300",
                step.status === "done" && "text-white/70",
                step.status === "active" && "text-white",
                step.status === "pending" && "text-white/35"
              )}
            >
              {step.label}
              {step.status === "active" && (
                <motion.span
                  className="inline-block ml-1"
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 1, repeat: Infinity }}
                >
                  _
                </motion.span>
              )}
            </span>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}
