import { Select as BaseSelect } from "@base-ui/react/select";
import { Check, ChevronDown, ChevronUp } from "lucide-react";
import { forwardRef, type ComponentPropsWithoutRef } from "react";
import { cn } from "../../lib/utils";

export interface OarsSelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface OarsSelectProps
  extends Omit<ComponentPropsWithoutRef<"button">, "children" | "onChange" | "value"> {
  value: string | null;
  options: readonly OarsSelectOption[];
  onValueChange: (value: string) => void;
  placeholder?: string;
}

/**
 * The shared Oars select. Its popup is portaled to the document body so it is
 * not clipped by Mosaic panes, scroll regions, or modal bodies.
 */
export const OarsSelect = forwardRef<HTMLButtonElement, OarsSelectProps>(function OarsSelect(
  { value, options, onValueChange, placeholder, className, disabled, id, ...triggerProps },
  ref,
) {
  const items = options.map(({ value: optionValue, label }) => ({ value: optionValue, label }));

  return (
    <BaseSelect.Root<string>
      items={items}
      value={value}
      onValueChange={(nextValue) => {
        if (nextValue !== null) onValueChange(nextValue);
      }}
      disabled={disabled}
    >
      <BaseSelect.Trigger
        {...triggerProps}
        ref={ref}
        id={id}
        className={cn("oars-select-trigger", className)}
      >
        <BaseSelect.Value className="oars-select-value" placeholder={placeholder} />
        <BaseSelect.Icon className="oars-select-icon">
          <ChevronDown aria-hidden />
        </BaseSelect.Icon>
      </BaseSelect.Trigger>
      <BaseSelect.Portal>
        <BaseSelect.Positioner
          className="oars-select-positioner"
          sideOffset={5}
          align="start"
          alignItemWithTrigger={false}
        >
          <BaseSelect.Popup className="oars-select-popup">
            <BaseSelect.ScrollUpArrow className="oars-select-scroll-arrow" data-scroll-direction="up">
              <ChevronUp aria-hidden />
            </BaseSelect.ScrollUpArrow>
            <BaseSelect.List className="oars-select-list">
              {options.map((option) => (
                <BaseSelect.Item
                  key={option.value}
                  value={option.value}
                  disabled={option.disabled}
                  className="oars-select-item"
                >
                  <BaseSelect.ItemIndicator className="oars-select-item-indicator" keepMounted>
                    <Check aria-hidden />
                  </BaseSelect.ItemIndicator>
                  <BaseSelect.ItemText className="oars-select-item-text">{option.label}</BaseSelect.ItemText>
                </BaseSelect.Item>
              ))}
            </BaseSelect.List>
            <BaseSelect.ScrollDownArrow className="oars-select-scroll-arrow" data-scroll-direction="down">
              <ChevronDown aria-hidden />
            </BaseSelect.ScrollDownArrow>
          </BaseSelect.Popup>
        </BaseSelect.Positioner>
      </BaseSelect.Portal>
    </BaseSelect.Root>
  );
});
