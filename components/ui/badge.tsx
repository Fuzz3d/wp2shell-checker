import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium tracking-wide uppercase",
  {
    variants: {
      variant: {
        neutral: "bg-white/[0.05] text-muted-foreground border border-white/10",
        primary: "bg-primary/15 text-primary border border-primary/25",
        success: "bg-success/15 text-success border border-success/25",
        warning: "bg-warning/15 text-warning border border-warning/25",
        danger: "bg-danger/15 text-danger border border-danger/25",
      },
    },
    defaultVariants: { variant: "neutral" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
