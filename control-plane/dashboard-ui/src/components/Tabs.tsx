import { Link } from "@tanstack/react-router";

interface TabItem {
  to: string;
  label: string;
}

interface TabsProps {
  items: TabItem[];
}

const baseCls =
  "px-3.5 py-2.5 text-xs border-b-2 transition-colors";

// Using the function-form className so the base classes stay present
// on the active tab. `activeProps.className` replaces the string form
// which drops padding / border-b-2, leaving the tab layout broken.
export function Tabs({ items }: TabsProps) {
  return (
    <nav className="flex gap-1 px-5 border-b border-border bg-panel">
      {items.map((item) => (
        <Link
          key={item.to}
          to={item.to}
          className={baseCls + " text-muted border-transparent hover:text-neutral-100"}
          activeProps={{ className: baseCls + " text-neutral-100 border-accent" }}
        >
          {item.label}
        </Link>
      ))}
    </nav>
  );
}
