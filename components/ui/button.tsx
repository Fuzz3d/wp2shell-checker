"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-medium transition-all duration-200 disabled:pointer-events-none disabled:opacity-40 focus-visible:outline-none",
  {
    variants: {
      variant: {
        primary:
          "bg-primary text-white shadow-[0_1px_0_rgba(255,255,255,0.2)_inset,0_8px_24px_-8px_rgba(79,140,255,0.6)] hover:bg-[#5e97ff] hover:shadow-[0_1px_0_rgba(255,255,255,0.25)_inset,0_12px_32px_-8px_rgba(79,140,255,0.7)] active:scale-[0.98]",
        secondary:
          "bg-white/[0.04] text-white border border-white/10 hover:bg-white/[0.07] hover:border-white/15 active:scale-[0.98]",
        ghost:
          "text-muted-foreground hover:text-white hover:bg-white/[0.04]",
        danger:
          "bg-danger text-white shadow-[0_1px_0_rgba(255,255,255,0.2)_inset,0_8px_24px_-8px_rgba(255,95,109,0.6)] hover:bg-[#ff7686] active:scale-[0.98]",
        success:
          "bg-success text-white shadow-[0_1px_0_rgba(255,255,255,0.2)_inset,0_8px_24px_-8px_rgba(22,196,127,0.5)] hover:brightness-110 active:scale-[0.98]",
      },
      size: {
        sm: "h-9 px-4",
        md: "h-11 px-5",
        lg: "h-12 px-6 text-[15px]",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  )
);
Button.displayName = "Button";
