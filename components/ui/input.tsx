"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "flex h-12 w-full rounded-xl bg-black/30 border border-white/10 px-4 text-[15px] text-white placeholder:text-muted-foreground/70 transition-all duration-200",
        "hover:border-white/15",
        "focus:outline-none focus:border-primary/50 focus:bg-black/40 focus:shadow-[0_0_0_3px_rgba(79,140,255,0.15),0_0_24px_-4px_rgba(79,140,255,0.3)]",
        "disabled:opacity-50",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";
