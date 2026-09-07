"use client";

import type { Variants } from "motion/react";
import { motion, useAnimation, useReducedMotion } from "motion/react";
import type { HTMLAttributes } from "react";
import { forwardRef, useCallback, useImperativeHandle, useRef } from "react";

export interface ArrowDownRightIconHandle {
  startAnimation: () => void;
  stopAnimation: () => void;
}

interface ArrowDownRightIconProps extends HTMLAttributes<HTMLDivElement> {
  size?: number;
}

const HEAD_VARIANTS: Variants = {
  normal: { translateX: 0, translateY: 0 },
  animate: { translateX: [0, -3, 0], translateY: [0, -3, 0], transition: { duration: 0.5, ease: "easeInOut" } },
};
const SHAFT_VARIANTS: Variants = {
  normal: { translateX: 0, translateY: 0, scale: 1 },
  animate: { translateX: [0, -3, 0], translateY: [0, -3, 0], scale: [1, 0.85, 1], originX: 1, originY: 1, transition: { duration: 0.5, ease: "easeInOut" } },
};

const ArrowDownRightIcon = forwardRef<ArrowDownRightIconHandle, ArrowDownRightIconProps>(
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
          <motion.path animate={controls} d="M7 7 L17 17" variants={SHAFT_VARIANTS} />
          <motion.path animate={controls} d="M17 7v10H7" variants={HEAD_VARIANTS} />
          <motion.path animate={controls} d="M17 17 L10 17" variants={HEAD_VARIANTS} />
        </svg>
      </div>
    );
  },
);

ArrowDownRightIcon.displayName = "ArrowDownRightIcon";

export { ArrowDownRightIcon };
