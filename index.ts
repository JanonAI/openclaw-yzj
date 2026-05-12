import type { OpenclawPluginApi } from "./src/compat.ts";
import { emptyPluginConfigSchema } from "./src/compat.ts";

import { handleYZJWebhookRequest } from "./src/monitor.ts";
import { setYZJRuntime } from "./src/runtime.ts";
import { yzjPlugin } from "./src/channel.ts";

const plugin = {
  id: "yzj",
  name: "YZJ",
  description: "OpenClaw YZJ (Yunzhijia) intelligent bot channel plugin",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenclawPluginApi) {
    setYZJRuntime(api.runtime);
    api.registerChannel({ plugin: yzjPlugin });
    api.registerHttpRoute({
      path: "/yzj",
      handler: handleYZJWebhookRequest,
      auth: "plugin",
      match: "prefix",
    });
  },
};

export default plugin;
