"use client";

import type { Variants } from "motion/react";
import { motion, useAnimation, useReducedMotion } from "motion/react";
import type { HTMLAttributes } from "react";
import { forwardRef, useCallback, useImperativeHandle, useRef } from "react";

export interface ArrowUpRightIconHandle {
  startAnimation: () => void;
  stopAnimation: () => void;
}

interface ArrowUpRightIconProps extends HTMLAttributes<HTMLDivElement> {
  size?: number;
}

const ARROW_VARIANTS: Variants = {
  normal: { scale: 1, translateX: 0, translateY: 0 },
  animate: { scale: [1, 0.85, 1], translateX: [0, -4, 0], translateY: [0, 4, 0], originX: 1, originY: 0, transition: { duration: 0.5, ease: "easeInOut" } },
};

const ArrowUpRightIcon = forwardRef<ArrowUpRightIconHandle, ArrowUpRightIconProps>(
  ({ onMouseEnter, onMouseLeave, className, size = 28, ...props }, ref) => {
    const controls = useAnimation();
    const isControlledRef = useRef(false);
    const reduceMotion = useReducedMotion();

    const start = useCallback(() => {
      if (!reduceMotion) void controls.start("animate");
    }, [controls, reduceMotion]);
    const stop = useCallback(() => { void controls.start("normal"); }, [controls]);

    useImperativeHandle(ref, () => {
      isControlledRef.current = true;
      return { startAnimation: start, stopAnimation: stop };
    }, [start, stop]);

    const handleMouseEnter = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
      if (!isControlledRef.current) start();
      onMouseEnter?.(event);
    }, [onMouseEnter, start]);
    const handleMouseLeave = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
      if (!isControlledRef.current) stop();
      onMouseLeave?.(event);
    }, [onMouseLeave, stop]);

    return (
      <div className={className} onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave} {...props}>
        <svg fill="none" height={size} stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" width={size} xmlns="http://www.w3.org/2000/svg">
          <motion.g animate={controls} variants={ARROW_VARIANTS}><path d="M7 7H17" /><path d="M17 7V17" /><path d="M7 17L17 7" /></motion.g>
        </svg>
      </div>
    );
  },
);

ArrowUpRightIcon.displayName = "ArrowUpRightIcon";

export { ArrowUpRightIcon };
