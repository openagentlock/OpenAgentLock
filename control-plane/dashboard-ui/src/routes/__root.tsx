import { Outlet, createRootRoute } from "@tanstack/react-router";
import { Header } from "@/components/Header";
import { Tabs } from "@/components/Tabs";
import { useModeInfo } from "@/hooks/usePoll";
import { apiBase } from "@/lib/api";

function RootLayout() {
  const { mode } = useModeInfo();
  return (
    <div className="min-h-screen text-neutral-100">
      <Header apiBase={apiBase()} mode={mode} />
      <Tabs
        items={[
          { to: "/events", label: "Events" },
          { to: "/rules", label: "Rules" },
          { to: "/sessions", label: "Sessions" },
          { to: "/mcp", label: "MCP" },
        ]}
      />
      <main className="p-5">
        <Outlet />
      </main>
    </div>
  );
}

export const Route = createRootRoute({
  component: RootLayout,
});
