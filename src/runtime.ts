/**
 * YZJ Robot Webhook 运行时管理器
 *
 * 负责管理运行时引用的生命周期
 */

import type { PluginRuntime } from './compat.ts';

let currentRuntime: PluginRuntime | null = null;

/**
 * 设置 YZJ 运行时
 */
export function setYZJRuntime(runtime: PluginRuntime): void {
  currentRuntime = runtime;
}

/**
 * 获取 YZJ 运行时
 */
export function getYZJRuntime(): PluginRuntime {
  if (!currentRuntime) {
    throw new Error("YZJ runtime not initialized");
  }
  return currentRuntime;
}
