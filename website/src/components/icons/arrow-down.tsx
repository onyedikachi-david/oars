"use client";

import type { Variants } from "motion/react";
import { motion, useAnimation, useReducedMotion } from "motion/react";
import type { HTMLAttributes } from "react";
import { forwardRef, useCallback, useImperativeHandle, useRef } from "react";

export interface ArrowDownIconHandle {
  startAnimation: () => void;
  stopAnimation: () => void;
}

interface ArrowDownIconProps extends HTMLAttributes<HTMLDivElement> {
  size?: number;
}

const PATH_VARIANTS: Variants = {
  normal: { d: "m19 12-7 7-7-7", translateY: 0 },
  animate: { d: "m19 12-7 7-7-7", translateY: [0, -3, 0], transition: { duration: 0.4 } },
};
const SECOND_PATH_VARIANTS: Variants = {
  normal: { d: "M12 5v14" },
  animate: { d: ["M12 5v14", "M12 5v9", "M12 5v14"], transition: { duration: 0.4 } },
};

const ArrowDownIcon = forwardRef<ArrowDownIconHandle, ArrowDownIconProps>(
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
          <motion.path animate={controls} d="m19 12-7 7-7-7" variants={PATH_VARIANTS} />
          <motion.path animate={controls} d="M12 5v14" variants={SECOND_PATH_VARIANTS} />
        </svg>
      </div>
    );
  },
);

ArrowDownIcon.displayName = "ArrowDownIcon";

export { ArrowDownIcon };
